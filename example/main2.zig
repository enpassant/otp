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

    var buf: [8]u8 = undefined;

    const totp = otp.Totp.init(&buf, otp.Options{
        .algorithm = .Sha1,
        .digits = 6,
    });

    while (try file.read(&line) > 0) {
        var iter = std.mem.tokenize(u8, &line, " :=");
        while (iter.next()) |token| {
            if (std.mem.eql(u8, token, "key")) {
                key = token;
            } else if (std.mem.eql(u8, token, "issuer")) {
                issuer = token;
            }
        } else {}

        var key_buf: [20]u8 = undefined;
        var seed = otp.decodeBase32(&key_buf, "N33FQ34E4SGPICGY");
        var totp_code = try totp.generateCode(seed, std.time.timestamp());
        var remaining_time = totp.remainingTime(std.time.timestamp());
        print("code: {s}, {d}s\n", .{ totp_code, remaining_time });

        // otpauth://totp/UlyVPN:TOTP0466A960?secret=DQAC63LA5PCQFSHAWPEPEOJG7CYDPJXF
        seed = otp.decodeBase32(&key_buf, "DQAC63LA5PCQFSHAWPEPEOJG7CYDPJXF");
        totp_code = try totp.generateCode(seed, std.time.timestamp());
        remaining_time = totp.remainingTime(std.time.timestamp());
        print("code: {s}, {d}s\n", .{ totp_code, remaining_time });
    }
}
