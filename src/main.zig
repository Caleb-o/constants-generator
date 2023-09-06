const std = @import("std");
const Allocator = std.mem.Allocator;

const Table = std.ArrayList(Value);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) {
        std.debug.panic("Error: Memory leaked!\n", .{});
    };
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len != 2) {
        std.debug.print("Malformed input\n", .{});
        return;
    }

    var vm = VM.create(allocator);
    defer vm.cleanup();

    var constants: std.ArrayList(Value) = undefined;
    defer constants.deinit();

    if (std.mem.eql(u8, argv[1], "l")) {
        constants = try loadConstantsFromDisk("constants", &vm);

        for (constants.items) |constant| {
            constant.print();
            std.debug.print("\n", .{});
        }
    } else if (std.mem.eql(u8, argv[1], "s")) {
        constants = std.ArrayList(Value).init(allocator);

        push(&constants, Value{ .int = 100 });
        push(&constants, Value{ .boolean = false });
        push(&constants, Value{ .object = &(try Object.String.fromLiteral(&vm, "Hello!")).object });

        const func = try Object.Function.create(&vm, "foo_bar", 1);
        try func.code.appendSlice(&[_]u8{
            @as(u8, @intFromEnum(ByteCode.ConstantByte)),
            @as(u8, 3),
            @as(u8, @intFromEnum(ByteCode.Return)),
        });
        push(&constants, Value{ .object = &func.object });

        try writeConstantsToDisk("constants", &constants);
    } else {
        std.debug.print("Incorrect argument '{s}'\n", .{argv[1]});
    }
}

inline fn push(list: *std.ArrayList(Value), value: Value) void {
    list.append(value) catch std.debug.panic("OOM", .{});
}

fn writeConstantsToDisk(fileName: [:0]const u8, list: *std.ArrayList(Value)) !void {
    var file = try std.fs.cwd().createFile(fileName, .{});
    defer file.close();

    var writer = file.writer();
    try writer.writeInt(usize, list.items.len, .Big);

    for (list.items) |*value| {
        const id = value.getTypeId();
        try writer.writeInt(u8, id, .Big);

        switch (value.*) {
            .int, .boolean => try value.write(&writer),
            .object => |o| {
                switch (o.kind) {
                    .String => try o.asString().write(&writer),
                    .Function => try o.asFunction().write(&writer),
                }
            },
        }
    }

    std.debug.print("Wrote {d} constants out to '{s}'\n", .{ list.items.len, fileName });
}

fn loadConstantsFromDisk(fileName: [:0]const u8, vm: *VM) !std.ArrayList(Value) {
    var file = try std.fs.cwd().openFile(fileName, .{});
    defer file.close();

    var constants = std.ArrayList(Value).init(vm.allocator);

    var reader = file.reader();
    const count = try reader.readInt(usize, .Big);

    for (0..count) |_| {
        const typeId = try reader.readInt(u8, .Big);
        const value = try Value.read(typeId, &reader, vm);
        try constants.append(value);
    }

    std.debug.print("Loaded {d} constants from '{s}'\n", .{ constants.items.len, fileName });

    return constants;
}

const ByteCode = enum(u8) {
    ConstantByte,
    Return,
};

const VM = struct {
    allocator: Allocator,
    objects: ?*Object,

    const Self = @This();

    inline fn create(allocator: Allocator) Self {
        return .{ .allocator = allocator, .objects = null };
    }

    fn cleanup(self: *Self) void {
        var current = self.objects;
        while (current) |obj| {
            var next = obj.next;
            obj.destroy(self);
            current = next;
        }
    }
};

const Value = union(enum) {
    int: i32,
    boolean: bool,
    object: *Object,

    const Self = @This();

    pub fn write(self: *const Self, writer: *std.fs.File.Writer) !void {
        switch (self.*) {
            .int => |i| try writer.writeInt(i32, i, .Big),
            .boolean => |b| try writer.writeInt(u8, @as(u8, @intFromBool(b)), .Big),
            .object => |o| try o.write(writer),
        }
    }

    pub fn read(typeId: u8, reader: *std.fs.File.Reader, vm: *VM) !Self {
        switch (typeId) {
            0 => return Value{ .int = try reader.readInt(i32, .Big) },
            1 => {
                const value = try reader.readInt(u8, .Big);
                return Value{ .boolean = @as(u1, @intCast(value)) == 1 };
            },
            else => {
                var obj = try Object.read(typeId, reader, vm);
                return Value{ .object = obj };
            },
        }
    }

    pub fn print(self: *const Self) void {
        switch (self.*) {
            .int => |i| std.debug.print("{d}", .{i}),
            .boolean => |b| std.debug.print("{}", .{b}),
            .object => |o| o.print(),
        }
    }

    pub fn getTypeId(self: *const Self) u8 {
        return switch (self.*) {
            .int => 0,
            .boolean => 1,
            .object => |o| return switch (o.kind) {
                .String => 2,
                .Function => 3,
            },
        };
    }
};

const ObjectKind = enum(u8) {
    String,
    Function,
};

pub const Object = struct {
    kind: ObjectKind,
    next: ?*Object,

    const Self = @This();

    pub fn allocate(vm: *VM, comptime T: type, kind: ObjectKind) !*Self {
        const ptr = try vm.allocator.create(T);

        ptr.object = Self{
            .kind = kind,
            .next = vm.objects,
        };

        vm.objects = &ptr.object;

        return vm.objects.?;
    }

    pub fn destroy(self: *Self, vm: *VM) void {
        switch (self.kind) {
            .String => self.asString().destroy(vm),
            .Function => self.asFunction().destroy(vm),
        }
    }

    pub fn write(self: *Self, writer: *std.fs.File.Writer) !void {
        switch (self.kind) {
            .String => try self.asString().write(writer),
            .Function => try self.asFunction().write(writer),
        }
    }

    pub fn read(typeId: u8, reader: *std.fs.File.Reader, vm: *VM) !*Object {
        switch (typeId) {
            2 => _ = try String.read(reader, vm),
            3 => _ = try Function.read(reader, vm),
            else => unreachable,
        }

        return vm.objects.?;
    }

    pub fn print(self: *Self) void {
        switch (self.kind) {
            .String => std.debug.print("'{s}'", .{self.asString().chars}),
            .Function => {
                const func = self.asFunction();
                std.debug.print("func<'{s}', {d}>\n", .{ func.identifier.chars, func.paramCount });
                func.displayCode();
            },
        }
    }

    // Check
    pub inline fn isString(self: *const Self) bool {
        return self.kind == .String;
    }

    pub inline fn isFunction(self: *const Self) bool {
        return self.kind == .Function;
    }

    // "Cast"
    pub fn asString(self: *Self) *String {
        std.debug.assert(self.isString());
        return @fieldParentPtr(String, "object", self);
    }

    pub fn asFunction(self: *Self) *Function {
        std.debug.assert(self.isFunction());
        return @fieldParentPtr(Function, "object", self);
    }

    pub const String = struct {
        object: Self,
        hash: u32,
        chars: []const u8,

        pub fn create(vm: *VM, buffer: []const u8) !*String {
            const hash = getHash(buffer);

            const object = try Self.allocate(vm, String, .String);
            const str = object.asString();
            str.chars = buffer;
            str.hash = hash;

            return str;
        }

        pub fn fromLiteral(vm: *VM, source: []const u8) !*String {
            const buffer = try copyLiteral(vm, source);
            return try String.create(vm, buffer);
        }

        fn copyLiteral(vm: *VM, source: []const u8) ![]const u8 {
            const buffer = try vm.allocator.alloc(u8, source.len);
            std.mem.copy(u8, buffer, source);
            return buffer;
        }

        pub fn copy(vm: *VM, source: []const u8) !*String {
            return try String.create(vm, try copyLiteral(vm, source));
        }

        pub fn write(self: *const String, writer: *std.fs.File.Writer) !void {
            try writer.writeInt(usize, self.chars.len, .Big);
            _ = try writer.write(self.chars);
        }

        pub fn read(reader: *std.fs.File.Reader, vm: *VM) !*String {
            const char_count = try reader.readInt(usize, .Big);
            var buffer = try vm.allocator.alloc(u8, char_count);
            const chars_read = try reader.read(buffer);
            std.debug.assert(chars_read == char_count);

            return try Object.String.create(vm, buffer);
        }

        pub inline fn destroy(self: *String, vm: *VM) void {
            vm.allocator.free(self.chars);
            vm.allocator.destroy(self);
        }

        fn getHash(buffer: []const u8) u32 {
            var hash: u32 = 2166136261;
            for (buffer) |byte| {
                hash ^= @as(u32, byte);
                hash *%= 16777619;
            }
            return hash;
        }
    };

    pub const Function = struct {
        object: Self,
        identifier: *String,
        paramCount: u8,
        code: std.ArrayList(u8),

        pub fn create(vm: *VM, identifier: []const u8, paramCount: u8) !*Function {
            const id = try String.fromLiteral(vm, identifier);

            const object = try Self.allocate(vm, Function, .Function);
            const func = object.asFunction();
            func.identifier = id;
            func.paramCount = paramCount;
            func.code = std.ArrayList(u8).init(vm.allocator);

            return func;
        }

        pub inline fn destroy(self: *const Function, vm: *VM) void {
            self.code.deinit();
            vm.allocator.destroy(self);
        }

        pub fn write(self: *const Function, writer: *std.fs.File.Writer) !void {
            try self.identifier.write(writer);
            try writer.writeInt(u8, self.paramCount, .Big);
            try writer.writeInt(usize, self.code.items.len, .Big);
            const written = try writer.write(self.code.items);
            std.debug.assert(written == self.code.items.len);
        }

        pub fn read(reader: *std.fs.File.Reader, vm: *VM) !*Function {
            const id = try String.read(reader, vm);

            const paramCount = try reader.readInt(u8, .Big);
            const codeCount = try reader.readInt(usize, .Big);

            const codeBytes = try vm.allocator.alloc(u8, codeCount);
            defer vm.allocator.free(codeBytes);

            const readBytes = try reader.read(codeBytes);
            std.debug.assert(readBytes == codeBytes.len);

            var code = try std.ArrayList(u8).initCapacity(vm.allocator, codeCount);
            try code.appendSlice(codeBytes);

            std.debug.assert(code.items.len == codeCount);

            const object = try Self.allocate(vm, Function, .Function);
            const func = object.asFunction();
            func.identifier = id;
            func.paramCount = paramCount;
            func.code = code;

            return func;
        }

        pub fn displayCode(self: *const Function) void {
            var ip: usize = 0;
            while (ip < self.code.items.len) {
                std.debug.print("{d:0>4} ", .{ip});

                switch (@as(ByteCode, @enumFromInt(self.code.items[ip]))) {
                    .ConstantByte => debugByteInstruction(&ip, "CONSTANT_BYTE", self.code.items),
                    .Return => debugSimpleInstruction(&ip, "RETURN"),
                }
            }
        }
    };
};

fn debugSimpleInstruction(ip: *usize, label: [:0]const u8) void {
    std.debug.print("{s}\n", .{label});
    ip.* += 1;
}

fn debugByteInstruction(ip: *usize, label: [:0]const u8, code: []u8) void {
    const byte = code[ip.* + 1];
    std.debug.print("{s} {d}\n", .{ label, byte });
    ip.* += 2;
}
