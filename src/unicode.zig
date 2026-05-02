//! UTF-8 utility functions replacing unicode.c from the C codebase.

const std = @import("std");

/// Returns the byte length of the last UTF-8 character in the
/// null-terminated string, or 0 if the string is empty.
/// Does not validate correct UTF-8 encoding.
pub fn utf8LastSize(str: [*:0]const u8) i32 {
    const s = std.mem.sliceTo(str, 0);
    if (s.len == 0) return 0;
    var i: usize = s.len;
    var len: i32 = 0;
    while (i > 0) {
        i -= 1;
        len += 1;
        if ((s[i] & 0xc0) != 0x80) return len;
    }
    return 0;
}

/// Returns the number of bytes needed to encode a codepoint
/// as UTF-8.
pub fn utf8Chsize(ch: u32) usize {
    if (ch > 0x10FFFF) return 4;
    return std.unicode.utf8CodepointSequenceLength(
        @intCast(ch),
    ) catch 4;
}

/// Encodes a codepoint as UTF-8 into str, returning the byte
/// length written. Falls back to manual encoding for surrogates
/// and out-of-range values.
pub fn utf8Encode(str: []u8, ch: u32) usize {
    if (ch <= 0x10FFFF) {
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(
            @intCast(ch),
            &buf,
        ) catch return encodeManual(str, ch);
        @memcpy(str[0..n], buf[0..n]);
        return n;
    }
    return encodeManual(str, ch);
}

// Manual UTF-8 encoder without validation. Handles surrogates
// and out-of-range codepoints matching the original C behaviour.
fn encodeManual(str: []u8, ch_in: u32) usize {
    var ch = ch_in;
    var first: u8 = undefined;
    var len: usize = undefined;
    if (ch < 0x80) {
        first = 0;
        len = 1;
    } else if (ch < 0x800) {
        first = 0xc0;
        len = 2;
    } else if (ch < 0x10000) {
        first = 0xe0;
        len = 3;
    } else {
        first = 0xf0;
        len = 4;
    }
    var i: usize = len - 1;
    while (i > 0) : (i -= 1) {
        str[i] = @as(u8, @truncate(ch & 0x3f)) | 0x80;
        ch >>= 6;
    }
    str[0] = @as(u8, @truncate(ch)) | first;
    return len;
}
