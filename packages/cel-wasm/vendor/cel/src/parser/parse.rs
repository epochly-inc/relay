//! Relay fork (G7/G8): string and bytes literal decoding.
//!
//! This module is a faithful port of cel-go's `parser/unescape.go`
//! (`unescape` + `unescapeChar`, github.com/google/cel-go v0.28.1), which is
//! the canonical CEL literal decoder. The previous cel-rust decoder
//! (`parse_string` / `parse_bytes`) diverged from CEL in three load-bearing
//! ways that this port corrects:
//!
//!   * **G7 (triple-quote delimiters).** `'''...'''` / `"""..."""` (and their
//!     raw `r`/`R` forms) had their inner `''` / `""` delimiter span left in
//!     the decoded value. cel-go strips the full triple-quote delimiter
//!     (`value[3:n-3]`) before decoding. The byte caller also pre-stripped a
//!     single trailing quote (`string[2..len-1]`), which is wrong for the
//!     triple-quote forms.
//!   * **G8 (escape set + quote context).** cel-rust restricted `\"` / `\'`
//!     based on the surrounding quote character and never accepted `\X`
//!     (upper-case hex). CEL's escape set is quote-context independent: `\?`,
//!     `\"`, `\'`, `` \` `` all decode to the bare character regardless of the
//!     opening quote, and both `\x` and `\X` are valid hex byte escapes.
//!   * **bytes vs string semantics.** For bytes, `\x`/`\X` and octal escapes
//!     denote raw byte values (no unicode encoding), and `\u`/`\U` are
//!     rejected. For strings they denote unicode code points. cel-rust applied
//!     a single rule to both.
//!
//! The decoder operates on raw bytes (`Vec<u8>`) to model cel-go faithfully
//! (cel-go returns a Go `string`, then `[]byte(...)` for the bytes literal).
//! For string literals the caller converts the resulting bytes to a `String`
//! via UTF-8 validation; cel-go's non-bytes path only emits valid UTF-8
//! (source is UTF-8 and `\u`/`\U`/octal code points are range-validated).

/// Error type for [`unescape`].
#[derive(Debug, PartialEq)]
pub enum ParseSequenceError {
    /// The literal was malformed (missing/mismatched quotes, too short, or an
    /// invalid/unsupported escape sequence). `msg` carries the cel-go-equivalent
    /// reason for diagnostics.
    Invalid { msg: String },
}

impl ParseSequenceError {
    fn invalid(msg: &str) -> Self {
        ParseSequenceError::Invalid {
            msg: msg.to_string(),
        }
    }
}

/// Port of cel-go `unhex`: decode a single ASCII hex digit.
fn unhex(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some((b - b'0') as u32),
        b'a'..=b'f' => Some((b - b'a' + 10) as u32),
        b'A'..=b'F' => Some((b - b'A' + 10) as u32),
        _ => None,
    }
}

/// Normalize newlines to `\n` (cel-go `newlineNormalizer`): `\r\n` -> `\n`,
/// then any remaining `\r` -> `\n`.
fn normalize_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// Result of decoding one (possibly escaped) character: the produced code
/// point / byte value, whether it should be UTF-8 encoded, and the remaining
/// input. Mirrors cel-go `unescapeChar`'s `(value, encode, tail, err)`.
struct DecodedChar {
    value: u32,
    encode: bool,
    consumed: usize,
}

/// Port of cel-go `unescapeChar`. `s` is the remaining byte slice; returns the
/// decoded character and the number of bytes consumed from `s`.
fn unescape_char(s: &[u8], is_bytes: bool) -> Result<DecodedChar, ParseSequenceError> {
    let c0 = s[0];

    // 1. Not an escape sequence.
    if c0 >= 0x80 {
        // Multi-byte UTF-8 lead: decode the full rune and pass it through with
        // encode=true (cel-go: utf8.DecodeRuneInString).
        let rest = std::str::from_utf8(s)
            .map_err(|_| ParseSequenceError::invalid("invalid utf-8 in string literal"))?;
        let ch = rest
            .chars()
            .next()
            .ok_or_else(|| ParseSequenceError::invalid("invalid utf-8 in string literal"))?;
        return Ok(DecodedChar {
            value: ch as u32,
            encode: true,
            consumed: ch.len_utf8(),
        });
    }
    if c0 != b'\\' {
        return Ok(DecodedChar {
            value: c0 as u32,
            encode: false,
            consumed: 1,
        });
    }

    // 2. Trailing backslash with no escape body.
    if s.len() <= 1 {
        return Err(ParseSequenceError::invalid(
            "unable to unescape string, found '\\' as last character",
        ));
    }

    let c = s[1];
    let body = &s[2..];

    // 3. Common single-character escapes (quote-context independent).
    let simple: Option<u32> = match c {
        b'a' => Some(0x07),
        b'b' => Some(0x08),
        b'f' => Some(0x0C),
        b'n' => Some(0x0A),
        b'r' => Some(0x0D),
        b't' => Some(0x09),
        b'v' => Some(0x0B),
        b'\\' => Some(b'\\' as u32),
        b'\'' => Some(b'\'' as u32),
        b'"' => Some(b'"' as u32),
        b'`' => Some(b'`' as u32),
        b'?' => Some(b'?' as u32),
        _ => None,
    };
    if let Some(value) = simple {
        return Ok(DecodedChar {
            value,
            encode: false,
            consumed: 2,
        });
    }

    // 4. Hex / unicode escapes.
    match c {
        b'x' | b'X' | b'u' | b'U' => {
            let (n, encode) = match c {
                b'x' | b'X' => (2usize, !is_bytes),
                b'u' => {
                    if is_bytes {
                        return Err(ParseSequenceError::invalid("unable to unescape string"));
                    }
                    (4usize, true)
                }
                b'U' => {
                    if is_bytes {
                        return Err(ParseSequenceError::invalid("unable to unescape string"));
                    }
                    (8usize, true)
                }
                _ => unreachable!(),
            };
            if body.len() < n {
                return Err(ParseSequenceError::invalid("unable to unescape string"));
            }
            let mut v: u32 = 0;
            for &hb in &body[..n] {
                let x = unhex(hb)
                    .ok_or_else(|| ParseSequenceError::invalid("unable to unescape string"))?;
                v = (v << 4) | x;
            }
            if !is_bytes && char::from_u32(v).is_none() {
                return Err(ParseSequenceError::invalid("invalid unicode code point"));
            }
            Ok(DecodedChar {
                value: v,
                encode,
                consumed: 2 + n,
            })
        }
        // 5. Octal escape: must be three digits \[0-3][0-7][0-7].
        b'0'..=b'3' => {
            if body.len() < 2 {
                return Err(ParseSequenceError::invalid(
                    "unable to unescape octal sequence in string",
                ));
            }
            let mut v: u32 = (c - b'0') as u32;
            for &ob in &body[..2] {
                if !(b'0'..=b'7').contains(&ob) {
                    return Err(ParseSequenceError::invalid(
                        "unable to unescape octal sequence in string",
                    ));
                }
                v = v * 8 + (ob - b'0') as u32;
            }
            if !is_bytes && char::from_u32(v).is_none() {
                return Err(ParseSequenceError::invalid("invalid unicode code point"));
            }
            Ok(DecodedChar {
                value: v,
                encode: !is_bytes,
                consumed: 4,
            })
        }
        // Unknown escape sequence.
        _ => Err(ParseSequenceError::invalid("unable to unescape string")),
    }
}

/// Relay fork (G7/G8): faithful port of cel-go `unescape`.
///
/// `value` is the literal token text WITHOUT the bytes `b`/`B` prefix (the
/// caller strips that first, matching cel-go `VisitBytes` `GetText()[1:]`). It
/// still includes any `r`/`R` raw prefix and the surrounding (single or triple)
/// quotes. Returns the decoded raw byte sequence.
pub fn unescape(value: &str, is_bytes: bool) -> Result<Vec<u8>, ParseSequenceError> {
    // All strings normalize newlines to `\n`.
    let value = normalize_newlines(value);
    let mut bytes: &[u8] = value.as_bytes();
    let mut n = bytes.len();

    if n < 2 {
        return Err(ParseSequenceError::invalid("unable to unescape string"));
    }

    // Raw string prefix r|R.
    let mut is_raw = false;
    if bytes[0] == b'r' || bytes[0] == b'R' {
        bytes = &bytes[1..];
        n = bytes.len();
        is_raw = true;
    }

    if n < 2 {
        return Err(ParseSequenceError::invalid("unable to unescape string"));
    }

    // Quoted string: first and last char must match and be a quote.
    let first = bytes[0];
    let last = bytes[n - 1];
    if first != last || (first != b'"' && first != b'\'') {
        return Err(ParseSequenceError::invalid("unable to unescape string"));
    }

    // Strip a triple-quote delimiter if present (G7).
    if n >= 6 {
        let is_triple_single = bytes.starts_with(b"'''");
        let is_triple_double = bytes.starts_with(b"\"\"\"");
        if is_triple_single {
            if !bytes.ends_with(b"'''") {
                return Err(ParseSequenceError::invalid("unable to unescape string"));
            }
            bytes = &bytes[3..n - 3];
            n = bytes.len();
        } else if is_triple_double {
            if !bytes.ends_with(b"\"\"\"") {
                return Err(ParseSequenceError::invalid("unable to unescape string"));
            }
            bytes = &bytes[3..n - 3];
            n = bytes.len();
        } else {
            // Single-quoted: strip the one outer quote on each side.
            bytes = &bytes[1..n - 1];
            n = bytes.len();
        }
    } else {
        // Too short for a triple quote: strip the single outer quotes.
        bytes = &bytes[1..n - 1];
        n = bytes.len();
    }
    let _ = n;

    // Raw literal, or no backslash: nothing to unescape.
    if is_raw || !bytes.contains(&b'\\') {
        return Ok(bytes.to_vec());
    }

    // Decode character by character (cel-go's strconv/quote-derived loop).
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        let dc = unescape_char(rest, is_bytes)?;
        rest = &rest[dc.consumed..];
        if dc.value < 0x80 || !dc.encode {
            out.push(dc.value as u8);
        } else {
            // Unicode-encode the rune (validated above for the non-bytes path).
            let ch = char::from_u32(dc.value)
                .ok_or_else(|| ParseSequenceError::invalid("invalid unicode code point"))?;
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
    }
    Ok(out)
}

/// Relay fork (G7/G8): decode a string literal token (full token text including
/// any `r`/`R` prefix and quotes) into a `String`. The decoded bytes must be
/// valid UTF-8 (cel-go's non-bytes path only ever produces valid UTF-8).
pub fn parse_string(s: &str) -> Result<String, ParseSequenceError> {
    let bytes = unescape(s, false)?;
    String::from_utf8(bytes)
        .map_err(|_| ParseSequenceError::invalid("invalid utf-8 in decoded string literal"))
}

/// Relay fork (G7/G8): decode a bytes literal body (the token text WITHOUT the
/// leading `b`/`B`, still carrying any `r`/`R` prefix and quotes) into raw
/// bytes.
pub fn parse_bytes(s: &str) -> Result<Vec<u8>, ParseSequenceError> {
    unescape(s, true)
}

#[cfg(test)]
mod tests {
    use super::{parse_bytes, parse_string};

    fn s(x: &str) -> String {
        parse_string(x).expect("parse_string")
    }
    fn b(x: &str) -> Vec<u8> {
        parse_bytes(x).expect("parse_bytes")
    }

    #[test]
    fn single_quoted_escapes_match_cel_go() {
        assert_eq!(s("'Hello \\a'"), "Hello \u{07}");
        assert_eq!(s("'Hello \\b'"), "Hello \u{08}");
        assert_eq!(s("'Hello \\v'"), "Hello \u{0b}");
        assert_eq!(s("'Hello \\f'"), "Hello \u{0c}");
        assert_eq!(s("'Hello \\n'"), "Hello \n");
        assert_eq!(s("'Hello \\r'"), "Hello \r");
        assert_eq!(s("'Hello \\t'"), "Hello \t");
        assert_eq!(s("'Hello \\\\'"), "Hello \\");
        assert_eq!(s("'Hello \\?'"), "Hello ?");
        assert_eq!(s("'Hello \\''"), "Hello '");
        assert_eq!(s("'Hello \\`'"), "Hello `");
        assert_eq!(s("'Hello \\x20'"), "Hello  ");
        assert_eq!(s("'Hello \\u270c'"), "Hello \u{270c}");
        assert_eq!(s("'Hello \\U0001f431'"), "Hello \u{1f431}");
        assert_eq!(s("'Hello \\040'"), "Hello  ");
    }

    #[test]
    fn g8_quote_context_independent() {
        // \" decodes to a bare quote even inside single quotes (cel-go drops
        // the backslash unconditionally).
        assert_eq!(s("' \\\\ \\? \\\" \\' \\` '"), " \\ ? \" ' ` ");
        // \' decodes to a bare quote even inside double quotes.
        assert_eq!(s("\" \\\\ \\? \\\" \\' \\` \""), " \\ ? \" ' ` ");
    }

    #[test]
    fn g8_upper_x_hex_escape() {
        assert_eq!(s("' \\X00 \\X0A \\X7F '"), " \u{00} \n \u{7f} ");
        assert_eq!(s("' \\x4a \\x4B \\X4c \\X4D '"), " J K L M ");
    }

    #[test]
    fn g7_triple_quoted_strings() {
        assert_eq!(s("''' ? \" ' ` '''"), " ? \" ' ` ");
        assert_eq!(s("\"\"\" ? \" ' ` \"\"\""), " ? \" ' ` ");
        assert_eq!(s("'''hello'''"), "hello");
        assert_eq!(s("\"\"\"hello\"\"\""), "hello");
    }

    #[test]
    fn g7_triple_quoted_bytes() {
        assert_eq!(b("'''hello'''"), b"hello".to_vec());
        assert_eq!(b("\"\"\"hello\"\"\""), b"hello".to_vec());
        // delimiter must be stripped, not embedded.
        assert_eq!(b("''' \\n '''"), vec![0x20, 0x0a, 0x20]);
    }

    #[test]
    fn bytes_escapes_and_punctuation() {
        // b' \\ \? \" \' \` ' -> 20 5c 20 3f 20 22 20 27 20 60 20
        assert_eq!(
            b("' \\\\ \\? \\\" \\' \\` '"),
            vec![0x20, 0x5c, 0x20, 0x3f, 0x20, 0x22, 0x20, 0x27, 0x20, 0x60, 0x20]
        );
        // control escapes in bytes
        assert_eq!(
            b("' \\a \\b \\f \\t \\v '"),
            vec![0x20, 0x07, 0x20, 0x08, 0x20, 0x0c, 0x20, 0x09, 0x20, 0x0b, 0x20]
        );
        // \x in bytes is a raw byte, no unicode encoding.
        assert_eq!(b("'\\xFF'"), vec![0xff]);
        assert_eq!(b("'\\377'"), vec![0xff]);
    }

    #[test]
    fn bytes_reject_unicode_escapes() {
        assert!(parse_bytes("'\\u0041'").is_err());
        assert!(parse_bytes("'\\U00000041'").is_err());
    }

    #[test]
    fn raw_strings_preserve_escapes() {
        assert_eq!(s("r'Hello \\n'"), "Hello \\n");
        assert_eq!(s("R\"Hello \\n\""), "Hello \\n");
        assert_eq!(s("r''' \\\\ \\? '''"), " \\\\ \\? ");
    }

    #[test]
    fn parses_legacy_bytes_smoke() {
        // historical cel-rust smoke: abc<heart>\xFF\376
        assert_eq!(
            b("'abc\u{1f496}\\xFF\\376'"),
            vec![97, 98, 99, 240, 159, 146, 150, 255, 254]
        );
    }
}
