const std = @import("std");
const fs = std.fs;
const print = std.debug.print;

const otp = @import("otp");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const file = try fs.cwd().openFile("otp.rc", .{});
    defer file.close();

    var buffer: [1024]u8 = undefined;
    var out_buffer: [1024]u8 = undefined;
    var key: ?[]const u8 = null;
    var issuer: ?[]const u8 = null;
    var key_buf: [20]u8 = undefined;
    var buf: [8]u8 = undefined;
    var options: otp.Options = .{};
    var in_stream = file.reader(&buffer);

    while (in_stream.interface.takeDelimiterExclusive('\n')) |line| {
        if (std.mem.startsWith(u8, line, "#")) {
            continue;
        }
        var iter = std.mem.tokenizeAny(u8, line, " :=\r\n");
        while (iter.next()) |token| {
            if (std.mem.eql(u8, token, "key")) {
                key = try std.mem.Allocator.dupe(allocator, u8, iter.next().?);
            } else if (std.mem.eql(u8, token, "Sha1")) {
                options.algorithm = .Sha1;
            } else if (std.mem.eql(u8, token, "Sha256")) {
                options.algorithm = .Sha256;
            } else if (std.mem.eql(u8, token, "6")) {
                options.digits = 6;
            } else if (std.mem.eql(u8, token, "7")) {
                options.digits = 7;
            } else if (std.mem.eql(u8, token, "8")) {
                options.digits = 8;
            } else if (std.mem.eql(u8, token, "30")) {
                options.time_step = 30;
            } else if (std.mem.eql(u8, token, "60")) {
                options.time_step = 60;
            } else if (std.mem.eql(u8, token, "issuer")) {
                issuer = try std.mem.Allocator.dupe(allocator, u8, iter.next().?);
            } else if (std.mem.eql(u8, token, "options") or token.len == 0 or token[0] == 0) {} else {
                print("Unknown token: {s}\n", .{token});
            }

            if (key != null and issuer != null) {
                const totp = otp.Totp.init(&buf, options);

                const seed = otp.decodeBase32(&key_buf, key.?);
                const totp_code = try totp.generateCode(seed, std.time.timestamp());
                const remaining_time = totp.remainingTime(std.time.timestamp());
                print("{s}: {s}, {d}s\n", .{
                    issuer.?,
                    totp_code,
                    remaining_time,
                });
                var stdout_writer = std.fs.File.stdout().writer(&out_buffer);
                var stdout = &stdout_writer.interface;
                try stdout.print("{s}: {s}\n", .{
                    issuer.?,
                    totp_code,
                });
                try stdout.flush();
                issuer = null;
                key = null;
                options = .{};
            }
        }
    } else |_| {}
}
