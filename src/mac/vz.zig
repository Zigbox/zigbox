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

/// `VZVirtualMachineState`, the values the host looks at.
const state_stopped: i64 = 0;
const state_running: i64 = 1;
const state_error: i64 = 3;

pub const State = enum { stopped, running, starting, stopping, other };

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
};

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
        configure(configuration, spec);
        var error_object: Id = null;
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
        var call: Call = .{ .machine = machine, .operation = .start, .waiter = objc.Waiter.init() };
        machine.queue.run(&call, &run_call);
        try wait(&call, .start, constants.vm_boot_timeout_ms, failure);
    }

    pub fn state(machine: *Machine) State {
        assert(machine.virtual_machine != null);
        var call: Call = .{ .machine = machine, .operation = .state, .waiter = objc.Waiter.init() };
        machine.queue.run(&call, &run_call);
        return switch (call.state) {
            state_stopped => .stopped,
            state_running => .running,
            4 => .starting,
            7 => .stopping,
            else => .other,
        };
    }

    /// True when the framework put the guest in its error state.
    pub fn errored(machine: *Machine) bool {
        assert(machine.virtual_machine != null);
        var call: Call = .{ .machine = machine, .operation = .state, .waiter = objc.Waiter.init() };
        machine.queue.run(&call, &run_call);
        return call.state == state_error;
    }

    /// Opens a vsock connection to `port` of the guest; the descriptor is the caller's to close.
    pub fn connect(machine: *Machine, port: u32, failure: *Failure) Error!i32 {
        assert(port <= 65535);
        assert(machine.virtual_machine != null);
        assert(port > 0);
        var call: Call = .{
            .machine = machine,
            .operation = .connect,
            .port = port,
            .waiter = objc.Waiter.init(),
        };
        machine.queue.run(&call, &run_call);
        try wait(&call, .connect, constants.vm_control_timeout_ms, failure);
        const connection = call.waiter.object orelse {
            failure.* = .{ .stage = .connect };
            return error.Failed;
        };
        defer objc.release(connection);
        const descriptor = objc.send(i32, connection, "fileDescriptor", .{});
        assert(descriptor >= 0);
        // The connection closes its descriptor when it is released; the caller keeps a copy.
        const copy = std.c.dup(descriptor);
        if (copy < 0) {
            failure.* = .{ .stage = .connect };
            return error.Failed;
        }
        return copy;
    }

    /// Stops the guest at once, as pulling the plug does. Used only when a clean stop did not
    /// happen in time.
    pub fn force_stop(machine: *Machine, failure: *Failure) Error!void {
        assert(constants.vm_stop_timeout_ms > 0);
        assert(machine.virtual_machine != null);
        var call: Call = .{ .machine = machine, .operation = .stop, .waiter = objc.Waiter.init() };
        machine.queue.run(&call, &run_call);
        try wait(&call, .stop, constants.vm_stop_timeout_ms, failure);
    }
};

const Operation = enum { start, state, connect, stop };

const Call = struct {
    machine: *Machine,
    operation: Operation,
    port: u32 = 0,
    waiter: objc.Waiter,
    state: i64 = -1,
};

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
        .state => call.state = objc.send(i64, machine, "state", .{}),
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
    assert(call.operation != .state);
    if (!call.waiter.wait(timeout_ms)) {
        failure.* = .{ .stage = stage };
        return error.Timeout;
    }
    if (call.waiter.failed) {
        failure.* = .{ .stage = stage, .info = call.waiter.info, .silent = false };
        return error.Failed;
    }
}

fn fail(failure: *Failure, stage: Stage, error_object: Id) void {
    assert(@backingInt(stage) <= @backingInt(Stage.stop));
    failure.* = .{ .stage = stage };
    if (error_object == null) return;
    objc.error_info(error_object, &failure.info);
    failure.silent = false;
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
    const entropy = objc.new("VZVirtioEntropyDeviceConfiguration");
    objc.send(void, configuration, "setEntropyDevices:", .{objc.array(&.{entropy})});
}
