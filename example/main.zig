const std = @import("std");
const fs = std.fs;
const otp = @import("otp");
const print = std.debug.print;

pub fn main() !void {
    const file = try fs.cwd().openFile("otp.rc", .{});
    defer file.close();

    var line: [200]u8 = undefined;
    var key: ?[]const u8 = null;
    var issuer: ?[]const u8 = null;
    var key_buf: [20]u8 = undefined;
    var buf: [8]u8 = undefined;
    var options: otp.Options = .{};

    while (try file.read(&line) > 0) {
        var iter = std.mem.tokenize(u8, &line, " :=\r\n");
        while (iter.next()) |token| {
            if (std.mem.eql(u8, token, "key")) {
                key = iter.next();
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
                issuer = iter.next();
            } else if (std.mem.eql(u8, token, "options") or token.len == 0 or token[0] == 0) {} else {
                print("Unknown token: {s}\n", .{token});
            }

            if (key != null and issuer != null) {
                const totp = otp.Totp.init(&buf, options);

                var seed = otp.decodeBase32(&key_buf, key.?);
                var totp_code = try totp.generateCode(seed, std.time.timestamp());
                var remaining_time = totp.remainingTime(std.time.timestamp());
                print("{s}: {s}, {d}s\n", .{
                    issuer.?,
                    totp_code,
                    remaining_time,
                });
                try std.io.getStdOut().writer().print("{s}: {s}\n", .{
                    issuer.?,
                    totp_code,
                });
                issuer = null;
                key = null;
                options = .{};
            }
        }
    }
}
