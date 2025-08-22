const builtin = @import("builtin");
const std = @import("std");
const crypto = std.crypto;

/// Possible errors when generating a code
pub const CodeGenError = error{
    /// OutOfBounds is triggered when digits is smaller than 6 or higher than 8.
    OutOfBounds,
    /// UnsupportedAlgorithm is triggered when an algorithm is passed of which is not supported.
    UnsupportedAlgorithm,
};

/// Supported hashing algorithms for generating an OTP.
/// Currently `Sha1` and `Sha256` are supported.
pub const Algorithm = enum {
    Sha1,
    Sha256,
};

/// Options can be provided to Totp to generate a code dependent on
/// the give `digits`, `algorithm` and `time_step`.
pub const Options = struct {
    digits: u8 = 6,
    algorithm: Algorithm = .Sha1,
    time_step: u8 = 30,
};

/// Hotp is a counter-based One Time password generator.
/// It implements `rfc4226` which can be found at
/// https://tools.ietf.org/html/rfc4226
pub const Hotp = struct {
    const Self = @This();

    digits: u8 = 6,
    buffer: []u8 = undefined,

    /// Init creates a new Hotp struct with the `digits` set by default to 6.
    pub fn init(buf: []u8) Self {
        return .{ .buffer = buf };
    }

    /// generateCode creates a new code using the given secret.
    /// The counter needs to be synchronized between the client and server.
    /// It is up to the implementation to handle the synchronization, this library does not facilitate it.
    pub fn generateCode(self: Self, secret: []const u8, counter: u64) ![]u8 {
        const result = buildCode(
            self.buffer,
            secret,
            counter,
            self.digits,
            Algorithm.Sha1,
        );
        return result;
    }
};

/// Totp is a time-based One Time Password generator.
/// It implements `rfc6238` which can be found at
/// https://tools.ietf.org/html/rfc6238
pub const Totp = struct {
    const Self = @This();

    opts: Options,
    buffer: []u8 = undefined,

    /// Init creates a new Totp struct and handles the generated codes according to it.
    pub fn init(buf: []u8, opts: Options) Self {
        return .{ .buffer = buf, .opts = opts };
    }

    /// generateCode creates a new code with a length of `digits`.
    /// `timestamp` can be generated using `std.milliTimestamp`.
    pub fn generateCode(self: Self, secret: []const u8, time: i64) ![]u8 {
        const counter: u64 = @intCast(@divTrunc(time, self.opts.time_step));
        return buildCode(
            self.buffer,
            secret,
            counter,
            self.opts.digits,
            self.opts.algorithm,
        );
    }

    pub fn remainingTime(self: Self, time: i64) u8 {
        return self.opts.time_step -
            @as(u8, @intCast(@rem(time, self.opts.time_step)));
    }
};

fn charToBits(ch: u8) u5 {
    if (ch >= 'A' and ch <= 'Z')
        return @truncate(ch - 'A')
    else
        return @truncate(26 + ch - '2');
}

pub fn decodeBase32(out_buf: []u8, text: []const u8) []const u8 {
    const rem = @rem(text.len, 8);
    const pad_len = @divTrunc(rem * 5, 8);
    const len = @divTrunc(text.len, 8) * 5 + pad_len;
    var pos: usize = 0;
    var num: u16 = 0;
    var bit_pos: u4 = 11;
    for (text) |ch| {
        const bits: u5 = charToBits(ch);
        num |= @shlExact(@as(u16, bits), bit_pos);
        if (bit_pos > 8)
            bit_pos -= 5
        else {
            out_buf[pos] = @truncate((num & 0xff00) >> 8);
            num = (num & 0xff) << 8;
            bit_pos += 8 - 5;
            pos += 1;
        }
    }
    return out_buf[0..len];
}

/// generateCode creates the actual code given the provided parameters from the `Hotp` & `Totp` structs.
fn buildCode(out_buf: []u8, secret: []const u8, counter: u64, digits: u8, algorithm: Algorithm) ![]u8 {
    if (digits < 6 or digits > 8) {
        return CodeGenError.OutOfBounds;
    }

    var buf: []u8 = undefined;

    switch (algorithm) {
        .Sha1 => {
            const hmac = crypto.auth.hmac.HmacSha1;
            var buffer: [hmac.mac_length]u8 = undefined;
            var counter_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter_buf, counter, std.builtin.Endian.big);
            var ctx = hmac.init(secret);
            ctx.update(counter_buf[0..]);
            ctx.final(buffer[0..]);
            buf = buffer[0..buffer.len];
        },
        .Sha256 => {
            const hmac = crypto.auth.hmac.sha2.HmacSha256;
            var buffer: [hmac.mac_length]u8 = undefined;
            var counter_buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &counter_buf, counter, std.builtin.Endian.big);
            var ctx = hmac.init(secret);
            ctx.update(counter_buf[0..]);
            ctx.final(buffer[0..]);
            buf = buffer[0..buffer.len];
        },
        // else => {
        //     return CodeGenError.UnsupportedAlgorithm;
        // },
    }

    // Truncate HS (HS = Hmac(key, counter))
    // https://tools.ietf.org/html/rfc4226#section-5.4
    const offset = buf[buf.len - 1] & 0xf;
    const bin_code: u32 = @as(u32, (buf[offset] & 0x7f)) << 24 |
        @as(u32, (buf[offset + 1] & 0xff)) << 16 |
        @as(u32, (buf[offset + 2] & 0xff)) << 8 |
        @as(u32, (buf[offset + 3] & 0xff));

    // add padding to the left incase the first number is a 0
    const code = bin_code % std.math.pow(u32, 10, digits);
    const len = formatCode(out_buf, code, digits);
    // std.mem.copy(u8, out_buf, result[0..digits]);
    return out_buf[0..len];
}

/// formatCode will try to parse the integer and return a string.
/// An extra `0` will be added to the left to match the given length.
fn formatCode(buf: []u8, val: u32, length: u8) usize {
    const len = std.fmt.formatIntBuf(buf, val, 10, .lower, std.fmt.FormatOptions{ .width = length, .fill = '0' });
    return len;
}

test "HOTP code generation" {
    var buf: [8]u8 = undefined;
    const hotp = Hotp.init(&buf);
    const code = try hotp.generateCode("secretkey", 0);
    try std.testing.expectEqualSlices(u8, "049381", code);
}

test "HOTP 8 digits" {
    var buf: [8]u8 = undefined;
    var hotp = Hotp.init(&buf);
    hotp.digits = 8;
    const code = try hotp.generateCode("secretkey", 0);
    try std.testing.expectEqualSlices(u8, "74049381", code);
}

test "HOTP different counters" {
    var buf: [8]u8 = undefined;
    const hotp = Hotp.init(&buf);
    var code = try hotp.generateCode("secretkey", 1);
    try std.testing.expectEqualSlices(u8, "534807", code);

    code = try hotp.generateCode("secretkey", 2);
    try std.testing.expectEqualSlices(u8, "155320", code);

    code = try hotp.generateCode("secretkey", 3);
    try std.testing.expectEqualSlices(u8, "642297", code);

    code = try hotp.generateCode("secretkey", 4);
    try std.testing.expectEqualSlices(u8, "964223", code);

    code = try hotp.generateCode("secretkey", 5);
    try std.testing.expectEqualSlices(u8, "416848", code);
}

test "TOTP code generation" {
    var buf: [8]u8 = undefined;
    var totp = Totp.init(&buf, Options{
        .algorithm = .Sha1,
        .digits = 8,
    });
    const time = 1587915766;
    var code = try totp.generateCode("secretkey", time);
    try std.testing.expectEqualSlices(u8, "68623043", code);
    // Test data from https://www.rfc-editor.org/rfc/rfc6238 Appendix B.
    code = try totp.generateCode("12345678901234567890", 59);
    try std.testing.expectEqualSlices(u8, "94287082", code);
    code = try totp.generateCode("12345678901234567890", 1111111109);
    try std.testing.expectEqualSlices(u8, "07081804", code);
    code = try totp.generateCode("12345678901234567890", 1111111111);
    try std.testing.expectEqualSlices(u8, "14050471", code);
    code = try totp.generateCode("12345678901234567890", 1234567890);
    try std.testing.expectEqualSlices(u8, "89005924", code);
    code = try totp.generateCode("12345678901234567890", 2000000000);
    try std.testing.expectEqualSlices(u8, "69279037", code);
    code = try totp.generateCode("12345678901234567890", 20000000000);
    try std.testing.expectEqualSlices(u8, "65353130", code);

    const totp_256 = Totp.init(&buf, Options{
        .algorithm = .Sha256,
        .digits = 8,
    });
    code = try totp_256.generateCode("12345678901234567890123456789012", 59);
    try std.testing.expectEqualSlices(u8, "46119246", code);
    code = try totp_256.generateCode("12345678901234567890123456789012", 1111111109);
    try std.testing.expectEqualSlices(u8, "68084774", code);
    code = try totp_256.generateCode("12345678901234567890123456789012", 1111111111);
    try std.testing.expectEqualSlices(u8, "67062674", code);
    code = try totp_256.generateCode("12345678901234567890123456789012", 1234567890);
    try std.testing.expectEqualSlices(u8, "91819424", code);
    code = try totp_256.generateCode("12345678901234567890123456789012", 2000000000);
    try std.testing.expectEqualSlices(u8, "90698825", code);
    code = try totp_256.generateCode("12345678901234567890123456789012", 20000000000);
    try std.testing.expectEqualSlices(u8, "77737706", code);
}

test "Base32 decode" {
    var buf: [40]u8 = undefined;
    const result = decodeBase32(&buf, "BAFYBEICZSSCDSBS7FFQZ55ASQDF3SMV6KLCW3GOFSZVWLYARCI47BGF354");
    const key = [_]u8{ 0x08, 0x0b, 0x80, 0x91, 0x02, 0xcc, 0xa4, 0x21, 0xc8, 0x32, 0xf9, 0x4b, 0x0c, 0xf7, 0xa0, 0x94, 0x06, 0x5d, 0xc9, 0x95, 0xf2, 0x96, 0x2b, 0x6c, 0xce, 0x2c, 0xb3, 0x5b, 0x2f, 0x00, 0x88, 0x91, 0xcf, 0x84, 0xc5, 0xdf };
    try std.testing.expectEqualSlices(u8, &key, result);
}
