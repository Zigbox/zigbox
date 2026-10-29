//! The Objective-C bridge: the one module that talks to the Objective-C runtime, Foundation's
//! few value classes and libdispatch, so that every other file of the macOS `zbx` is plain Zig.
//! Nothing here is third-party: the runtime's C functions are declared by hand and Virtualization
//! .framework is reached through them (`objc_msgSend` cast to the signature of each call).
//!
//! Rules this module keeps for its callers:
//!   - A message send names its return type and the exact C types of its arguments; there is no
//!     variadic magic. `send` supports up to five arguments, which is all Virtualization needs.
//!   - A completion handler is a block literal built by hand (`Block`). It is a stack block with
//!     no captured variables of its own: the state it needs is behind its `context` pointer, and
//!     the caller keeps that state alive until the handler has run (it waits on a `Waiter`).
//!   - A framework `NSError` becomes an `ErrorInfo` (domain, code, description) in fixed buffers;
//!     it is never printed as the object it is.
//!   - Virtualization objects are only touched on the VM's serial dispatch queue: `Queue.run`.

const std = @import("std");
const assert = std.debug.assert;
const builtin = @import("builtin");

comptime {
    // The runtime and blocks ABI declared below are the arm64 Apple ones.
    assert(builtin.os.tag == .macos);
    assert(builtin.cpu.arch == .aarch64);
}

pub const Id = ?*anyopaque;
pub const Selector = *anyopaque;

extern "c" fn objc_getClass(name: [*:0]const u8) Id;
extern "c" fn sel_registerName(name: [*:0]const u8) Selector;
extern "c" fn objc_msgSend() void;
extern "c" fn objc_autoreleasePoolPush() ?*anyopaque;
extern "c" fn objc_autoreleasePoolPop(pool: ?*anyopaque) void;
extern "c" var _NSConcreteStackBlock: [32]?*anyopaque;

extern "c" fn dispatch_queue_create(label: [*:0]const u8, attributes: ?*anyopaque) ?*anyopaque;
extern "c" fn dispatch_sync_f(
    queue: ?*anyopaque,
    context: ?*anyopaque,
    work: *const fn (?*anyopaque) callconv(.c) void,
) void;
extern "c" fn dispatch_semaphore_create(value: i64) ?*anyopaque;
extern "c" fn dispatch_semaphore_wait(semaphore: ?*anyopaque, timeout: u64) i64;
extern "c" fn dispatch_semaphore_signal(semaphore: ?*anyopaque) i64;
extern "c" fn dispatch_time(base: u64, delta_ns: i64) u64;

const dispatch_time_now: u64 = 0;
const nanoseconds_per_millisecond: i64 = 1_000_000;

/// The text parts of an `NSError` kept for a diagnostic.
pub const error_text_bytes_max: u32 = 256;
pub const error_domain_bytes_max: u32 = 64;

/// Sends `selector` to `target` and returns a `Return`. `arguments` is a tuple of values whose
/// types are the C types of the method's parameters (`u64` for an NSUInteger, `bool` for BOOL,
/// `Id` for an object, `?*anyopaque` for a pointer).
pub fn send(comptime Return: type, target: Id, selector: [:0]const u8, arguments: anytype) Return {
    assert(target != null); // A message to nil is a bug in the caller; ObjC would hide it.
    const sel = sel_registerName(selector.ptr);
    const address = @intFromPtr(&objc_msgSend);
    const Arguments = @TypeOf(arguments);
    const fields = comptime std.meta.fieldTypes(Arguments);
    comptime assert(fields.len <= 5);
    switch (fields.len) {
        0 => {
            const call: *const fn (Id, Selector) callconv(.c) Return = @ptrFromInt(address);
            return call(target, sel);
        },
        1 => {
            const call: *const fn (Id, Selector, fields[0]) callconv(.c) Return =
                @ptrFromInt(address);
            return call(target, sel, arguments[0]);
        },
        2 => {
            const call: *const fn (
                Id,
                Selector,
                fields[0],
                fields[1],
            ) callconv(.c) Return = @ptrFromInt(address);
            return call(target, sel, arguments[0], arguments[1]);
        },
        3 => {
            const call: *const fn (
                Id,
                Selector,
                fields[0],
                fields[1],
                fields[2],
            ) callconv(.c) Return = @ptrFromInt(address);
            return call(target, sel, arguments[0], arguments[1], arguments[2]);
        },
        4 => {
            const call: *const fn (
                Id,
                Selector,
                fields[0],
                fields[1],
                fields[2],
                fields[3],
            ) callconv(.c) Return = @ptrFromInt(address);
            return call(target, sel, arguments[0], arguments[1], arguments[2], arguments[3]);
        },
        else => {
            const call: *const fn (
                Id,
                Selector,
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                fields[4],
            ) callconv(.c) Return = @ptrFromInt(address);
            const a = arguments;
            return call(target, sel, a[0], a[1], a[2], a[3], a[4]);
        },
    }
}

/// The class named `name`; a framework class that is missing is a bug (or a framework not linked).
pub fn class(name: [:0]const u8) Id {
    const found = objc_getClass(name.ptr);
    assert(found != null);
    assert(name.len > 0);
    return found;
}

/// `[[Class alloc] init]`, owned by the caller (never autoreleased).
pub fn new(name: [:0]const u8) Id {
    const allocated = send(Id, class(name), "alloc", .{});
    assert(allocated != null);
    const made = send(Id, allocated, "init", .{});
    assert(made != null);
    return made;
}

pub fn release(object: Id) void {
    assert(object != null);
    send(void, object, "release", .{});
}

/// An autorelease pool for a stretch of code that makes autoreleased objects (the class
/// constructors below). A command line tool has none unless it makes one.
pub const Pool = struct {
    token: ?*anyopaque,

    pub fn push() Pool {
        const token = objc_autoreleasePoolPush();
        assert(token != null);
        return .{ .token = token };
    }

    pub fn pop(pool: Pool) void {
        assert(pool.token != null);
        objc_autoreleasePoolPop(pool.token);
    }
};

/// An `NSString` for a UTF-8 text, autoreleased.
pub fn string(text: [:0]const u8) Id {
    const pointer: ?[*:0]const u8 = text.ptr;
    const made = send(Id, class("NSString"), "stringWithUTF8String:", .{pointer});
    assert(made != null);
    return made;
}

/// `[NSURL fileURLWithPath:]`, autoreleased.
pub fn file_url(path: [:0]const u8) Id {
    assert(path.len > 0);
    const made = send(Id, class("NSURL"), "fileURLWithPath:", .{string(path)});
    assert(made != null);
    return made;
}

/// An `NSArray` of the objects, autoreleased.
pub fn array(objects: []const Id) Id {
    assert(objects.len <= 16);
    const made = send(Id, class("NSArray"), "arrayWithObjects:count:", .{
        @as(?[*]const Id, objects.ptr),
        @as(u64, objects.len),
    });
    assert(made != null);
    return made;
}

/// `[[NSFileHandle alloc] initWithFileDescriptor:closeOnDealloc:]`, autoreleased.
pub fn file_handle(descriptor: i32, close_on_dealloc: bool) Id {
    assert(descriptor >= 0);
    const allocated = send(Id, class("NSFileHandle"), "alloc", .{});
    const made = send(Id, allocated, "initWithFileDescriptor:closeOnDealloc:", .{
        descriptor, close_on_dealloc,
    });
    assert(made != null);
    return send(Id, made, "autorelease", .{});
}

/// The UTF-8 bytes of an `NSString` copied into `buffer` (cut at the buffer's end, always
/// NUL-terminated); an empty text for nil.
pub fn copy_text(text: Id, buffer: []u8) []const u8 {
    assert(buffer.len >= 2);
    buffer[0] = 0;
    if (text == null) return buffer[0..0];
    const pointer = send(?[*:0]const u8, text, "UTF8String", .{}) orelse return buffer[0..0];
    const source = std.mem.span(pointer);
    const length = @min(source.len, buffer.len - 1);
    @memcpy(buffer[0..length], source[0..length]);
    buffer[length] = 0;
    return buffer[0..length];
}

/// What a framework error says, in fixed buffers.
pub const ErrorInfo = struct {
    domain_storage: [error_domain_bytes_max]u8 = undefined,
    domain_length: u32 = 0,
    code: i64 = 0,
    description_storage: [error_text_bytes_max]u8 = undefined,
    description_length: u32 = 0,

    pub fn domain(info: *const ErrorInfo) []const u8 {
        return info.domain_storage[0..info.domain_length];
    }

    pub fn description(info: *const ErrorInfo) []const u8 {
        return info.description_storage[0..info.description_length];
    }
};

/// Reads domain, code and localized description out of an `NSError`. This is the only place an
/// error object is looked at; callers turn the result into a cause and a fix.
pub fn error_info(error_object: Id, info: *ErrorInfo) void {
    assert(error_object != null);
    info.* = .{};
    const domain = copy_text(send(Id, error_object, "domain", .{}), &info.domain_storage);
    info.domain_length = @intCast(domain.len);
    info.code = send(i64, error_object, "code", .{});
    const text = send(Id, error_object, "localizedDescription", .{});
    const description = copy_text(text, &info.description_storage);
    info.description_length = @intCast(description.len);
    assert(info.domain_length < error_domain_bytes_max);
    assert(info.description_length < error_text_bytes_max);
}

// ---- Blocks -----------------------------------------------------------------------------------

const BlockDescriptor = extern struct {
    reserved: u64,
    size: u64,
};

/// The layout of a block literal (the clang blocks ABI): the class pointer, flags, the function
/// to call, and a descriptor. `context` follows the header, so the size in the descriptor covers
/// it and a copy made by the framework (`Block_copy`) carries it along.
pub const Block = extern struct {
    isa: ?*anyopaque,
    flags: i32,
    reserved: i32,
    invoke: *const anyopaque,
    descriptor: *const BlockDescriptor,
    context: ?*anyopaque,

    const descriptor_value: BlockDescriptor = .{ .reserved = 0, .size = @sizeOf(Block) };

    /// A block that calls `invoke` (a C function whose first parameter is `*Block`) and finds
    /// `context` in the block it is given.
    pub fn init(invoke: *const anyopaque, context: ?*anyopaque) Block {
        return .{
            .isa = &_NSConcreteStackBlock,
            .flags = 0,
            .reserved = 0,
            .invoke = invoke,
            .descriptor = &descriptor_value,
            .context = context,
        };
    }
};

/// Where a completion handler leaves its answer, and what the caller waits on.
pub const Waiter = struct {
    semaphore: ?*anyopaque,
    done: bool = false,
    failed: bool = false,
    info: ErrorInfo = .{},
    /// For a handler that is given an object: it, retained (`retain` in `finish`).
    object: Id = null,

    pub fn init() Waiter {
        const semaphore = dispatch_semaphore_create(0);
        assert(semaphore != null);
        return .{ .semaphore = semaphore };
    }

    /// Called by a handler with its `NSError` argument (nil for success) and its object, if any.
    pub fn finish(waiter: *Waiter, error_object: Id, object: Id) void {
        assert(!waiter.done);
        if (error_object != null) {
            waiter.failed = true;
            error_info(error_object, &waiter.info);
        }
        if (object != null) {
            _ = send(Id, object, "retain", .{});
            waiter.object = object;
        }
        waiter.done = true;
        _ = dispatch_semaphore_signal(waiter.semaphore);
    }

    /// True if the handler ran within `timeout_ms`.
    pub fn wait(waiter: *Waiter, timeout_ms: u32) bool {
        const delta = @as(i64, timeout_ms) * nanoseconds_per_millisecond;
        const when = dispatch_time(dispatch_time_now, delta);
        const timed_out = dispatch_semaphore_wait(waiter.semaphore, when) != 0;
        if (timed_out) return false;
        assert(waiter.done);
        return true;
    }
};

/// The handler of `^(NSError *error)`.
pub fn error_handler_invoke(block: *Block, error_object: Id) callconv(.c) void {
    const waiter: *Waiter = @ptrCast(@alignCast(block.context.?));
    waiter.finish(error_object, null);
}

/// The handler of `^(id object, NSError *error)`.
pub fn object_handler_invoke(block: *Block, object: Id, error_object: Id) callconv(.c) void {
    const waiter: *Waiter = @ptrCast(@alignCast(block.context.?));
    waiter.finish(error_object, object);
}

pub fn error_block(waiter: *Waiter) Block {
    return Block.init(@ptrCast(&error_handler_invoke), waiter);
}

pub fn object_block(waiter: *Waiter) Block {
    return Block.init(@ptrCast(&object_handler_invoke), waiter);
}

// ---- Dispatch queues --------------------------------------------------------------------------

const Work = fn (?*anyopaque) callconv(.c) void;

/// A serial dispatch queue: the one thread of control a virtual machine's objects live on.
pub const Queue = struct {
    handle: ?*anyopaque,

    pub fn create(label: [:0]const u8) Queue {
        const handle = dispatch_queue_create(label.ptr, null);
        assert(handle != null);
        return .{ .handle = handle };
    }

    /// Runs `work(context)` on the queue and returns when it is done.
    pub fn run(queue: Queue, context: ?*anyopaque, work: *const Work) void {
        assert(queue.handle != null);
        dispatch_sync_f(queue.handle, context, work);
    }
};

// ---- Tests ------------------------------------------------------------------------------------

test "a string round-trips through NSString and copy_text, cut at the buffer" {
    // Goal: the string helpers and the truncation rule. Method: make an NSString, read it back
    // into a buffer that fits it and into one that does not.
    const pool = Pool.push();
    defer pool.pop();
    const text = string("virtio-fs");
    var big: [32]u8 = @splat(0xaa);
    try std.testing.expectEqualStrings("virtio-fs", copy_text(text, &big));
    var small: [5]u8 = @splat(0xaa);
    try std.testing.expectEqualStrings("virt", copy_text(text, &small));
    try std.testing.expectEqual(@as(u8, 0), small[4]);
    try std.testing.expectEqualStrings("", copy_text(null, &small));
}

test "an NSError becomes domain, code and description" {
    // Goal: error_info reads a real framework error, the translation every diagnostic relies on.
    // Method: build an NSError with a known domain, code and description (userInfo).
    const pool = Pool.push();
    defer pool.pop();
    const keys = [_]Id{string("NSLocalizedDescription")};
    const values = [_]Id{string("the disk is full")};
    const make = "dictionaryWithObjects:forKeys:count:";
    const info_dictionary = send(Id, class("NSDictionary"), make, .{
        @as(?[*]const Id, &values),
        @as(?[*]const Id, &keys),
        @as(u64, 1),
    });
    const made = send(Id, class("NSError"), "errorWithDomain:code:userInfo:", .{
        string("VZErrorDomain"), @as(i64, 7), info_dictionary,
    });
    var info: ErrorInfo = undefined;
    error_info(made, &info);
    try std.testing.expectEqualStrings("VZErrorDomain", info.domain());
    try std.testing.expectEqual(@as(i64, 7), info.code);
    try std.testing.expectEqualStrings("the disk is full", info.description());
}

test "a hand-built block is called with its context and signals the waiter" {
    // Goal: the block ABI. Method: ask the runtime to call a block we built, as the framework
    // does for a completion handler: Block_copy it, call its invoke through the copy.
    const pool = Pool.push();
    defer pool.pop();
    var waiter = Waiter.init();
    var block = error_block(&waiter);
    const Copy = *const fn (*Block) callconv(.c) *Block;
    const block_copy: Copy = @ptrCast(&_Block_copy);
    const copied = block_copy(&block);
    const call: *const fn (*Block, Id) callconv(.c) void = @ptrCast(@alignCast(copied.invoke));
    try std.testing.expect(!waiter.wait(10));
    call(copied, null);
    try std.testing.expect(waiter.wait(1000));
    try std.testing.expect(!waiter.failed);
    _Block_release(copied);
}

extern "c" fn _Block_copy(block: *Block) *Block;
extern "c" fn _Block_release(block: *Block) void;

const QueueProbe = struct { value: u32 = 0 };

fn probe_work(context: ?*anyopaque) callconv(.c) void {
    const probe: *QueueProbe = @ptrCast(@alignCast(context.?));
    probe.value += 1;
}

test "queue work runs to completion before run returns" {
    // Goal: Queue.run is synchronous. Method: a counter changed by the work, read on return.
    var probe: QueueProbe = .{};
    const queue = Queue.create("zbx.test");
    queue.run(&probe, &probe_work);
    queue.run(&probe, &probe_work);
    try std.testing.expectEqual(@as(u32, 2), probe.value);
}
