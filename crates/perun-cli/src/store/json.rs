// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! Minimal JSON parser — the iTunes Search API and the DAAP storefront
//! pages return JSON, and pulling serde_json into a binary this focused is
//! overkill. Objects keep insertion order (Apple's API output is
//! effectively unordered, but stable iteration helps deterministic
//! downstream text output).

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Numbers kept as raw text: app IDs exceed f64 precision and prices
    /// need exact decimal output.
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// Numeric text — works for both Number and String nodes (the Store
    /// mixes them across endpoints).
    pub fn as_number(&self) -> Option<&str> {
        match self {
            Json::Number(n) => Some(n),
            Json::String(s) => {
                if s.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_digit() || c == '-')
                {
                    Some(s)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_number().and_then(|n| n.parse().ok())
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_number().and_then(|n| n.parse().ok())
    }

    #[allow(dead_code)]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(entries) => Some(entries),
            _ => None,
        }
    }
}

pub fn parse(input: &str) -> Result<Json, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let value = p.value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(format!("trailing bytes at {}", p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while let Some(b) = self.bytes.get(self.pos) {
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at {}", b as char, self.pos))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("unexpected byte at {}", self.pos)),
        }
    }

    fn literal(&mut self, text: &str, value: Json) -> Result<Json, String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(value)
        } else {
            Err(format!("bad literal at {}", self.pos))
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'.' || c == b'e' || c == b'E' || c == b'+' || c == b'-' {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(format!("bad number at {}", start));
        }
        Ok(Json::Number(
            std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| "number utf8")?
                .to_string(),
        ))
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self
                .bytes
                .get(self.pos)
                .copied()
                .ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = self.bytes.get(self.pos).copied().ok_or("bad escape")?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hex = std::str::from_utf8(
                                self.bytes
                                    .get(self.pos..self.pos + 4)
                                    .ok_or("bad unicode escape")?,
                            )
                            .map_err(|_| "escape utf8")?;
                            let cp = u32::from_str_radix(hex, 16).map_err(|_| "bad hex")?;
                            self.pos += 4;
                            if (0xD800..0xDC00).contains(&cp) {
                                // Surrogate pair: expect the low half.
                                if self.bytes.get(self.pos) == Some(&b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    let hex2 = std::str::from_utf8(
                                        self.bytes
                                            .get(self.pos + 2..self.pos + 6)
                                            .ok_or("bad surrogate")?,
                                    )
                                    .map_err(|_| "escape utf8")?;
                                    let low =
                                        u32::from_str_radix(hex2, 16).map_err(|_| "bad hex")?;
                                    self.pos += 6;
                                    let combined = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                    out.push(char::from_u32(combined).unwrap_or('\u{FFFD}'));
                                } else {
                                    out.push('\u{FFFD}');
                                }
                            } else {
                                out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            }
                        }
                        _ => return Err("bad escape char".into()),
                    }
                }
                c if c < 0x20 => return Err("control char in string".into()),
                _ => {
                    // Collect UTF-8 bytes verbatim until a quote, escape, or
                    // control char — not past a backslash (it starts an
                    // escape sequence the next loop turn must consume).
                    let start = self.pos - 1;
                    let mut end = self.pos;
                    while end < self.bytes.len()
                        && self.bytes[end] >= 0x20
                        && self.bytes[end] != b'"'
                        && self.bytes[end] != b'\\'
                    {
                        end += 1;
                    }
                    // Re-read the full span including `c`.
                    let mut start2 = start;
                    while start2 > 0 && self.bytes[start2] & 0xC0 == 0x80 {
                        start2 -= 1;
                    }
                    let slice =
                        std::str::from_utf8(&self.bytes[start2..end]).map_err(|_| "string utf8")?;
                    out.push_str(slice);
                    self.pos = end;
                }
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut entries = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(entries));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value()?;
            entries.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(entries));
                }
                _ => return Err(format!("expected , or }} at {}", self.pos)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("expected , or ] at {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_objects_and_numbers() {
        let v = parse(r#"{"a": 1, "b": [true, null, "x"], "c": {"d": 2.5}}"#).unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(1));
        assert_eq!(v.get("b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(v.get("c").unwrap().get("d").unwrap().as_f64(), Some(2.5));
        assert_eq!(
            v.get("b").unwrap().as_array().unwrap()[2].as_str(),
            Some("x")
        );
    }

    #[test]
    fn big_ids_stay_exact() {
        let v = parse(r#"{"trackId": 3898012520849299233}"#).unwrap();
        // The point of Number-as-text: no f64 precision loss.
        assert_eq!(
            v.get("trackId").unwrap().as_number(),
            Some("3898012520849299233")
        );
    }

    #[test]
    fn escapes_and_unicode() {
        let v = parse(r#"{"s": "a\"b\\cA"}"#).unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("a\"b\\cA"));
        let v = parse(r#"{"s": "A"}"#).unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("A"));
        let v = parse(r#"{"s": "é"}"#).unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("é"));
        let v = parse(r#"{"s": "a\"b\\c\u0041\u00e9\ud83d\ude00"}"#).unwrap();
        assert_eq!(v.get("s").unwrap().as_str(), Some("a\"b\\cAé😀"));
    }

    #[test]
    fn malformed_inputs_rejected_cleanly() {
        // Every one of these must fail without panicking.
        let bad = [
            "",
            "{",
            "{\"a\"",
            "{\"a\":}",
            "{\"a\":1,}",
            "[1,2",
            "\"unterminated",
            "{\"a\": tru}",
            "{\"a\": \"\\u12\"}",
            "123a",
            "\"\\x\"",
        ];
        for input in bad {
            assert!(parse(input).is_err(), "accepted: {input:?}");
        }
    }

    #[test]
    fn big_object_and_array() {
        // 2000 keys, some with unicode — parse and spot-check.
        let mut body = String::from("{");
        for i in 0..2000 {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&format!("\"ключ-{i}\": \"значение-{i} 😀\"", i = i));
        }
        body.push('}');
        let v = parse(&body).unwrap();
        assert_eq!(v.get("ключ-0").unwrap().as_str(), Some("значение-0 😀"));
        assert_eq!(
            v.get("ключ-1999").unwrap().as_str(),
            Some("значение-1999 😀")
        );

        let mut arr = String::from("[");
        for i in 0..5000 {
            if i > 0 {
                arr.push(',');
            }
            arr.push_str(&i.to_string());
        }
        arr.push(']');
        let v = parse(&arr).unwrap();
        let items = v.as_array().unwrap();
        assert_eq!(items.len(), 5000);
        assert_eq!(items[4999].as_i64(), Some(4999));
    }

    #[test]
    fn number_formats() {
        // Negative, fractional, exponent, big integers keep exact digits.
        let v = parse("{\"a\": -17, \"b\": 3.5, \"c\": 1e3, \"d\": 9223372036854775807}").unwrap();
        assert_eq!(v.get("a").unwrap().as_i64(), Some(-17));
        assert_eq!(v.get("b").unwrap().as_f64(), Some(3.5));
        assert_eq!(v.get("d").unwrap().as_i64(), Some(9223372036854775807));
        // Numbers-as-text survive round-trip for exact large IDs.
        assert_eq!(v.get("d").unwrap().as_number(), Some("9223372036854775807"));
    }
    #[test]
    fn itunes_search_shape() {
        let body = r#"{"resultCount":1,"results":[{"trackId":686449807,"bundleId":"org.telegram.desktop","trackName":"Telegram","version":"11.0","price":0.0}]}"#;
        let v = parse(body).unwrap();
        let results = v.get("results").unwrap().as_array().unwrap();
        assert_eq!(results[0].get("trackId").unwrap().as_i64(), Some(686449807));
        assert_eq!(
            results[0].get("bundleId").unwrap().as_str(),
            Some("org.telegram.desktop")
        );
    }
}
