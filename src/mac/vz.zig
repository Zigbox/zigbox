//! Virtualization.framework, as much of it as the VM of milestone M4b needs: a Linux guest booted
//! from a kernel and an initramfs, a console written to a file, a vsock device, an entropy
//! device. Every call goes through `objc.zig`; every object of the virtual machine is touched
//! only on its dispatch queue (`Machine.queue`), as the framework requires.
//!
//! A failure is a `Failure`: the stage that failed and the framework's error as domain, code and
//! text. This file decides nothing about what the user sees; `diagnose.zig` turns a `Failure`
//! into a cause and a fix.

const std = @import("std");
const assert = std.debug.assert;
const objc = @import("objc.zig");
const constants = @import("../constants.zig");

const Id = objc.Id;

pub const Stage = enum { configure, validate, start, connect, stop };

pub const Failure = struct {
    stage: Stage = .configure,
    info: objc.ErrorInfo = .{},
    /// True when the framework said nothing (a timeout, a missing object).
    silent: bool = true,
};

pub const Error = error{ Unsupported, Failed, Timeout };

/// The sizes the framework allows on this Mac.
pub const Limits = struct {
    cpus_min: u32,
    cpus_max: u32,
    memory_bytes_min: u64,
    memory_bytes_max: u64,
};

/// `VZVirtualMachineState`, every value, so that none is mapped by a guess.
const state_stopped: i64 = 0;
const state_running: i64 = 1;
const state_paused: i64 = 2;
const state_error: i64 = 3;
const state_starting: i64 = 4;
const state_pausing: i64 = 5;
const state_resuming: i64 = 6;
const state_stopping: i64 = 7;
const state_saving: i64 = 8;
const state_restoring: i64 = 9;

pub const State = enum {
    stopped,
    running,
    paused,
    errored,
    starting,
    pausing,
    resuming,
    stopping,
    saving,
    restoring,
    /// A value this zbx does not know (a newer macOS).
    unknown,
};

/// Each framework state, named. The host acts on `stopped`, `errored` and `running`.
fn state_of(value: i64) State {
    assert(value >= -1);
    assert(value <= std.math.maxInt(i32));
    return switch (value) {
        state_stopped => .stopped,
        state_running => .running,
        state_paused => .paused,
        state_error => .errored,
        state_starting => .starting,
        state_pausing => .pausing,
        state_resuming => .resuming,
        state_stopping => .stopping,
        state_saving => .saving,
        state_restoring => .restoring,
        else => .unknown,
    };
}

pub fn supported() bool {
    assert(@sizeOf(Id) == 8);
    return objc.send(bool, objc.class("VZVirtualMachine"), "isSupported", .{});
}

pub fn limits() Limits {
    assert(constants.vm_cpus_min >= 1);
    const configuration = objc.class("VZVirtualMachineConfiguration");
    const cpus_min = objc.send(u64, configuration, "minimumAllowedCPUCount", .{});
    const cpus_max = objc.send(u64, configuration, "maximumAllowedCPUCount", .{});
    const memory_min = objc.send(u64, configuration, "minimumAllowedMemorySize", .{});
    const memory_max = objc.send(u64, configuration, "maximumAllowedMemorySize", .{});
    assert(cpus_min >= 1);
    assert(cpus_min <= cpus_max);
    assert(memory_min <= memory_max);
    return .{
        .cpus_min = @intCast(cpus_min),
        .cpus_max = @intCast(@min(cpus_max, std.math.maxInt(u32))),
        .memory_bytes_min = memory_min,
        .memory_bytes_max = memory_max,
    };
}

/// What the guest is booted with.
pub const BootSpec = struct {
    kernel_path: [:0]const u8,
    initramfs_path: [:0]const u8,
    command_line: [:0]const u8,
    /// An open file the console is written to.
    console_descriptor: i32,
    cpus: u32,
    memory_bytes: u64,
    /// The store disk: a file the guest sees as a virtio block device (`/dev/vda`).
    disk_path: [:0]const u8,
    /// The Mac user's home, shared read-write under the tag `home`.
    home_path: [:0]const u8,
    /// Whether to share Rosetta under the tag `rosetta`; only when it is installed.
    rosetta: bool,
};

/// Whether Rosetta for Linux can be shared with a guest on this Mac.
pub const RosettaState = enum { not_supported, not_installed, installed };

/// `VZLinuxRosettaDirectoryShare.availability`, every value of `VZLinuxRosettaAvailability`.
pub fn rosetta_state() RosettaState {
    const value = objc.send(i64, objc.class("VZLinuxRosettaDirectoryShare"), "availability", .{});
    assert(value >= 0);
    return switch (value) {
        1 => .not_installed,
        2 => .installed,
        else => .not_supported,
    };
}

/// A vsock connection: the caller's copy of the descriptor and the framework's object, which must
/// not be released while the connection is in use.
pub const Connection = struct {
    descriptor: i32,
    object: Id,
};

/// Ends a connection the caller used itself: closes the descriptor, then releases the object.
pub fn finish_connection(connection: Connection) void {
    assert(connection.descriptor >= 0);
    assert(connection.object != null);
    _ = std.c.close(connection.descriptor);
    objc.release(connection.object);
}

pub const Machine = struct {
    queue: objc.Queue,
    virtual_machine: Id,
    configuration: Id,

    /// Builds and validates the configuration. On failure `failure` says why.
    pub fn create(spec: *const BootSpec, failure: *Failure) Error!Machine {
        assert(spec.kernel_path.len > 0);
        assert(spec.initramfs_path.len > 0);
        assert(spec.cpus >= 1);
        assert(spec.memory_bytes % (1 << 20) == 0);
        if (!supported()) return error.Unsupported;
        const pool = objc.Pool.push();
        defer pool.pop();
        const configuration = objc.new("VZVirtualMachineConfiguration");
        var error_object: Id = null;
        configure(configuration, spec);
        if (!attach_storage(configuration, spec, &error_object)) {
            fail(failure, .configure, error_object);
            return error.Failed;
        }
        const valid = objc.send(bool, configuration, "validateWithError:", .{&error_object});
        if (!valid) {
            fail(failure, .validate, error_object);
            return error.Failed;
        }
        const queue = objc.Queue.create("zbx.vm");
        const allocated = objc.send(Id, objc.class("VZVirtualMachine"), "alloc", .{});
        const machine = objc.send(Id, allocated, "initWithConfiguration:queue:", .{
            configuration, queue.handle,
        });
        assert(machine != null);
        return .{ .queue = queue, .virtual_machine = machine, .configuration = configuration };
    }

    /// Starts the guest and waits for the framework to say it has started.
    pub fn start(machine: *Machine, failure: *Failure) Error!void {
        assert(constants.vm_boot_timeout_ms > 0);
        assert(machine.virtual_machine != null);
        const call = begin(machine, .start, 0);
        machine.queue.run(call, &run_call);
        try wait(call, .start, constants.vm_boot_timeout_ms, failure);
    }

    pub fn state(machine: *Machine) State {
        assert(machine.virtual_machine != null);
        var query: StateQuery = .{ .machine = machine };
        machine.queue.run(&query, &run_state);
        assert(query.value >= 0);
        return state_of(query.value);
    }

    /// True when the framework put the guest in its error state.
    pub fn errored(machine: *Machine) bool {
        assert(machine.virtual_machine != null);
        assert(!is_poisoned);
        return machine.state() == .errored;
    }

    /// True after an operation timed out: its completion handler may still run, so the machine
    /// is not used again. The host reports the failure and exits.
    pub fn poisoned(machine: *const Machine) bool {
        assert(machine.virtual_machine != null);
        return is_poisoned;
    }

    /// Opens a vsock connection to `port` of the guest. The framework closes the connection when
    /// its object is released (even if the descriptor was duplicated), so the object lives as
    /// long as the descriptor is in use: `finish_connection` when the caller is done with it, or
    /// the object is kept by whoever handed the descriptor on.
    pub fn connect(machine: *Machine, port: u32, failure: *Failure) Error!Connection {
        assert(port <= 65535);
        assert(machine.virtual_machine != null);
        assert(port > 0);
        const call = begin(machine, .connect, port);
        machine.queue.run(call, &run_call);
        try wait(call, .connect, constants.vm_control_timeout_ms, failure);
        const connection = call.waiter.object orelse {
            failure.* = .{ .stage = .connect };
            return error.Failed;
        };
        const descriptor = objc.send(i32, connection, "fileDescriptor", .{});
        assert(descriptor >= 0);
        // The caller works with a copy of the descriptor and closes it when it is done.
        const copy = std.c.dup(descriptor);
        if (copy < 0) {
            objc.release(connection);
            failure.* = .{ .stage = .connect };
            return error.Failed;
        }
        return .{ .descriptor = copy, .object = connection };
    }

    /// Stops the guest at once, as pulling the plug does. Used only when a clean stop did not
    /// happen in time.
    pub fn force_stop(machine: *Machine, failure: *Failure) Error!void {
        assert(constants.vm_stop_timeout_ms > 0);
        assert(machine.virtual_machine != null);
        const call = begin(machine, .stop, 0);
        machine.queue.run(call, &run_call);
        try wait(call, .stop, constants.vm_stop_timeout_ms, failure);
    }
};

/// The operations that finish through a completion handler.
const Operation = enum { start, connect, stop };

const Call = struct {
    machine: *Machine,
    operation: Operation,
    port: u32,
    waiter: objc.Waiter,
};

/// The framework keeps a completion handler's block, and with it a pointer to the state the
/// handler writes, until the handler runs, which can be after the caller gave up waiting. So that
/// state is never on a caller's stack: there is one slot per operation, in static storage, for
/// the life of the process. A timeout poisons the machine: the slot may still be written by the
/// late handler, so no operation reuses it, and the host reports the failure and exits.
var slots: [3]Call = undefined;
var slots_ready = false;
var is_poisoned = false;

fn slot_for(operation: Operation) *Call {
    assert(@backingInt(operation) < slots.len);
    if (!slots_ready) {
        for (&slots, std.enums.values(Operation)) |*made, kind| {
            made.* = .{
                .machine = undefined,
                .operation = kind,
                .port = 0,
                .waiter = objc.Waiter.init(),
            };
        }
        slots_ready = true;
    }
    assert(slots_ready);
    return &slots[@backingInt(operation)];
}

/// The operation's slot, made ready for a new call. A poisoned machine is never used again.
fn begin(machine: *Machine, operation: Operation, port: u32) *Call {
    assert(!is_poisoned);
    const call = slot_for(operation);
    call.waiter.reset();
    call.machine = machine;
    call.port = port;
    assert(call.operation == operation);
    return call;
}

const StateQuery = struct {
    machine: *Machine,
    value: i64 = -1,
};

fn run_state(context: ?*anyopaque) callconv(.c) void {
    assert(context != null);
    const query: *StateQuery = @ptrCast(@alignCast(context.?));
    assert(query.value == -1);
    assert(query.machine.virtual_machine != null);
    query.value = objc.send(i64, query.machine.virtual_machine, "state", .{});
}

fn run_call(context: ?*anyopaque) callconv(.c) void {
    assert(context != null);
    const call: *Call = @ptrCast(@alignCast(context.?));
    const machine = call.machine.virtual_machine;
    switch (call.operation) {
        .start => {
            var block = objc.error_block(&call.waiter);
            objc.send(void, machine, "startWithCompletionHandler:", .{&block});
        },
        .stop => {
            var block = objc.error_block(&call.waiter);
            objc.send(void, machine, "stopWithCompletionHandler:", .{&block});
        },
        .connect => {
            const devices = objc.send(Id, machine, "socketDevices", .{});
            const count = objc.send(u64, devices, "count", .{});
            if (count == 0) return call.waiter.finish(null, null);
            const device = objc.send(Id, devices, "objectAtIndex:", .{@as(u64, 0)});
            var block = objc.object_block(&call.waiter);
            objc.send(void, device, "connectToPort:completionHandler:", .{ call.port, &block });
        },
    }
}

fn wait(call: *Call, stage: Stage, timeout_ms: u32, failure: *Failure) Error!void {
    assert(call.waiter.semaphore != null);
    assert(timeout_ms > 0);
    if (!call.waiter.wait(timeout_ms)) {
        is_poisoned = true;
        failure.* = .{ .stage = stage };
        return error.Timeout;
    }
    if (call.waiter.failed) {
        failure.* = .{ .stage = stage, .info = call.waiter.info, .silent = false };
        return error.Failed;
    }
}

test "a handler that runs after its wait timed out writes only into its slot" {
    // Goal: the use-after-return this design removes. Method: take the start slot, let the wait
    // time out (poisoning the machine), then run the handler as the framework would, later and
    // from a copy of the block. The slot is static, so the write is safe; it must show the
    // completion, and the machine must stay poisoned.
    const pool = objc.Pool.push();
    defer pool.pop();
    var stand_in: Machine = undefined;
    stand_in.virtual_machine = @ptrFromInt(8);
    const call = begin(&stand_in, .start, 0);
    var failure: Failure = .{};
    try std.testing.expectError(error.Timeout, wait(call, .start, 1, &failure));
    try std.testing.expect(is_poisoned);
    try std.testing.expect(stand_in.poisoned());
    try std.testing.expect(!call.waiter.done);
    var block = objc.error_block(&call.waiter);
    const copy = objc.copy_block(&block);
    defer objc.release_block(copy);
    objc.call_error_block(copy, null);
    try std.testing.expect(call.waiter.done);
    try std.testing.expect(!call.waiter.failed);
    is_poisoned = false; // The test's machine was not real; other tests start clean.
}

test "every framework state maps to its own name" {
    // Goal: no state is guessed. Method: all ten values and one beyond.
    const names = [_]State{
        .stopped, .running,  .paused,   .errored, .starting,
        .pausing, .resuming, .stopping, .saving,  .restoring,
    };
    for (names, 0..) |name, value| {
        try std.testing.expectEqual(name, state_of(@intCast(value)));
    }
    try std.testing.expectEqual(State.unknown, state_of(10));
    try std.testing.expectEqual(State.unknown, state_of(-1));
}

fn fail(failure: *Failure, stage: Stage, error_object: Id) void {
    assert(@backingInt(stage) <= @backingInt(Stage.stop));
    failure.* = .{ .stage = stage };
    if (error_object == null) return;
    objc.error_info(error_object, &failure.info);
    failure.silent = false;
}

/// The store disk, the shared home and (when asked) Rosetta. False with `error_object` set when
/// the framework refuses one of them (a missing file, a Rosetta that went away).
fn attach_storage(configuration: Id, spec: *const BootSpec, error_object: *Id) bool {
    assert(spec.disk_path.len > 0);
    assert(spec.home_path.len > 0);
    const attachment_class = objc.class("VZDiskImageStorageDeviceAttachment");
    const disk_class = objc.send(Id, attachment_class, "alloc", .{});
    const init_disk = "initWithURL:readOnly:error:";
    const disk = objc.send(Id, disk_class, init_disk, .{
        objc.file_url(spec.disk_path), false, error_object,
    });
    if (disk == null) return false;
    const block_class = objc.send(Id, objc.class("VZVirtioBlockDeviceConfiguration"), "alloc", .{});
    const block = objc.send(Id, block_class, "initWithAttachment:", .{disk});
    objc.send(void, configuration, "setStorageDevices:", .{objc.array(&.{block})});
    const directory_class = objc.send(Id, objc.class("VZSharedDirectory"), "alloc", .{});
    const directory = objc.send(Id, directory_class, "initWithURL:readOnly:", .{
        objc.file_url(spec.home_path), false,
    });
    const single_class = objc.send(Id, objc.class("VZSingleDirectoryShare"), "alloc", .{});
    const single = objc.send(Id, single_class, "initWithDirectory:", .{directory});
    const home = share_device(constants.vm_home_tag, single);
    if (!spec.rosetta) {
        objc.send(void, configuration, "setDirectorySharingDevices:", .{objc.array(&.{home})});
        return true;
    }
    const rosetta_class = objc.send(Id, objc.class("VZLinuxRosettaDirectoryShare"), "alloc", .{});
    const rosetta = objc.send(Id, rosetta_class, "initWithError:", .{error_object});
    if (rosetta == null) return false;
    const translator = share_device(constants.vm_rosetta_tag, rosetta);
    const devices = objc.array(&.{ home, translator });
    objc.send(void, configuration, "setDirectorySharingDevices:", .{devices});
    return true;
}

/// A virtio-fs device that offers `share` to the guest under `tag`.
fn share_device(tag: [:0]const u8, share: Id) Id {
    assert(tag.len > 0);
    assert(share != null);
    const configuration_class = objc.class("VZVirtioFileSystemDeviceConfiguration");
    const device_class = objc.send(Id, configuration_class, "alloc", .{});
    const device = objc.send(Id, device_class, "initWithTag:", .{objc.string(tag)});
    objc.send(void, device, "setShare:", .{share});
    return device;
}

/// Fills the configuration: boot loader, CPUs, memory, platform, console, vsock, entropy.
fn configure(configuration: Id, spec: *const BootSpec) void {
    assert(spec.cpus >= 1);
    assert(spec.console_descriptor >= 0);
    const loader_class = objc.send(Id, objc.class("VZLinuxBootLoader"), "alloc", .{});
    const kernel_url = objc.file_url(spec.kernel_path);
    const loader = objc.send(Id, loader_class, "initWithKernelURL:", .{kernel_url});
    objc.send(void, loader, "setInitialRamdiskURL:", .{objc.file_url(spec.initramfs_path)});
    objc.send(void, loader, "setCommandLine:", .{objc.string(spec.command_line)});
    objc.send(void, configuration, "setBootLoader:", .{loader});
    objc.send(void, configuration, "setCPUCount:", .{@as(u64, spec.cpus)});
    objc.send(void, configuration, "setMemorySize:", .{spec.memory_bytes});
    objc.send(void, configuration, "setPlatform:", .{objc.new("VZGenericPlatformConfiguration")});
    const null_input = std.c.open("/dev/null", .{ .ACCMODE = .RDONLY });
    assert(null_input >= 0);
    const attachment_name = "VZFileHandleSerialPortAttachment";
    const attachment_class = objc.send(Id, objc.class(attachment_name), "alloc", .{});
    const initialiser = "initWithFileHandleForReading:fileHandleForWriting:";
    const attachment = objc.send(Id, attachment_class, initialiser, .{
        objc.file_handle(null_input, true),
        objc.file_handle(spec.console_descriptor, false),
    });
    const port = objc.new("VZVirtioConsoleDeviceSerialPortConfiguration");
    objc.send(void, port, "setAttachment:", .{attachment});
    objc.send(void, configuration, "setSerialPorts:", .{objc.array(&.{port})});
    const socket = objc.new("VZVirtioSocketDeviceConfiguration");
    objc.send(void, configuration, "setSocketDevices:", .{objc.array(&.{socket})});
    // The NAT network: the guest asks for an address by DHCP and reaches the Mac's network.
    const nic = objc.new("VZVirtioNetworkDeviceConfiguration");
    objc.send(void, nic, "setAttachment:", .{objc.new("VZNATNetworkDeviceAttachment")});
    objc.send(void, configuration, "setNetworkDevices:", .{objc.array(&.{nic})});
    const entropy = objc.new("VZVirtioEntropyDeviceConfiguration");
    objc.send(void, configuration, "setEntropyDevices:", .{objc.array(&.{entropy})});
}
