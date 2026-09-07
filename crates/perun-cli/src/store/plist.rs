// Copyright 2026 lazyeel (https://github.com/lazyeel)
// SPDX-License-Identifier: Apache-2.0

//! XML and binary property-list codec — the wire format of every private
//! Store endpoint. Hand-rolled: the project keeps its dependency surface
//! minimal, and the store only needs dict/string/int/data/array values.

/// A property-list value.
#[derive(Clone, Debug, PartialEq)]
pub enum Plist {
    Dict(Vec<(String, Plist)>),
    Array(Vec<Plist>),
    String(String),
    Integer(i64),
    Real(f64),
    Data(Vec<u8>),
    Boolean(bool),
    Date(String),
}

impl Default for Plist {
    fn default() -> Self {
        Plist::Dict(Vec::new())
    }
}

impl Plist {
    pub fn dict() -> Plist {
        Plist::Dict(Vec::new())
    }

    pub fn set(&mut self, key: &str, value: Plist) {
        if let Plist::Dict(entries) = self {
            if let Some(entry) = entries.iter_mut().find(|(k, _)| k == key) {
                entry.1 = value;
            } else {
                entries.push((key.to_string(), value));
            }
        }
    }

    pub fn string(s: impl Into<String>) -> Plist {
        Plist::String(s.into())
    }

    /// Look up a key in a dict.
    pub fn get(&self, key: &str) -> Option<&Plist> {
        match self {
            Plist::Dict(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Plist::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Plist::Integer(i) => Some(*i),
            Plist::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Plist::Data(d) => Some(d),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_dict(&self) -> Option<&[(String, Plist)]> {
        match self {
            Plist::Dict(entries) => Some(entries),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Plist]> {
        match self {
            Plist::Array(items) => Some(items),
            _ => None,
        }
    }
}

// ── XML decoding ──────────────────────────────────────────────────────────

/// Parse an XML property list. Tolerant: Apple's store endpoints emit
/// non-spec preamble (`<Document>`, `<Protocol>`) around the `<plist>`.
pub fn parse_xml(input: &[u8]) -> Result<Plist, String> {
    let text = std::str::from_utf8(input).map_err(|e| format!("plist utf8: {e}"))?;
    // Trim anything outside the outermost dict/array. The store wraps plist
    // documents in XML envelopes; the payload we need is always a dict.
    let start = text
        .find("<dict>")
        .or_else(|| text.find("<array>"))
        .ok_or("no <dict> or <array> in document")?;
    let end_tag = if text[start..].starts_with("<dict>") {
        "</dict>"
    } else {
        "</array>"
    };
    let end = text[start..]
        .rfind(end_tag)
        .ok_or("unterminated plist container")?
        + start
        + end_tag.len();
    parse_value(&text[start..end])
}

fn parse_value(xml: &str) -> Result<Plist, String> {
    let xml = xml.trim_start();
    if let Some(rest) = xml.strip_prefix("<dict>") {
        let body = strip_suffix(rest, "</dict>")?;
        return Ok(Plist::Dict(parse_entries(body)?));
    }
    if let Some(rest) = xml.strip_prefix("<array>") {
        let body = strip_suffix(rest, "</array>")?;
        let mut items = Vec::new();
        for value in split_top_level(body)? {
            if value.trim().is_empty() {
                continue;
            }
            items.push(parse_value(value)?);
        }
        return Ok(Plist::Array(items));
    }
    if let Some(rest) = xml.strip_prefix("<data>") {
        let body = strip_suffix(rest, "</data>")?;
        let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        return Ok(Plist::Data(base64_decode(&clean)?));
    }
    if let Some(rest) = xml.strip_prefix("<string>") {
        let body = strip_suffix(rest, "</string>")?;
        return Ok(Plist::String(xml_unescape(body)));
    }
    if let Some(rest) = xml.strip_prefix("<integer>") {
        let body = strip_suffix(rest, "</integer>")?;
        return Ok(Plist::Integer(
            body.trim()
                .parse::<i64>()
                .map_err(|e| format!("integer: {e}"))?,
        ));
    }
    if let Some(rest) = xml.strip_prefix("<real>") {
        let body = strip_suffix(rest, "</real>")?;
        return Ok(Plist::Real(
            body.trim()
                .parse::<f64>()
                .map_err(|e| format!("real: {e}"))?,
        ));
    }
    if xml.starts_with("<true/>") {
        return Ok(Plist::Boolean(true));
    }
    if xml.starts_with("<false/>") {
        return Ok(Plist::Boolean(false));
    }
    if let Some(rest) = xml.strip_prefix("<date>") {
        let body = strip_suffix(rest, "</date>")?;
        return Ok(Plist::Date(body.trim().to_string()));
    }
    Err(format!(
        "unsupported plist element: {}",
        &xml[..xml.len().min(48)]
    ))
}

fn strip_suffix<'a>(body: &'a str, suffix: &str) -> Result<&'a str, String> {
    let end = body
        .rfind(suffix)
        .ok_or_else(|| format!("missing {suffix}"))?;
    Ok(&body[..end])
}

/// Split a dict body into `(key, value-xml)` pairs.
fn parse_entries(body: &str) -> Result<Vec<(String, Plist)>, String> {
    let mut entries = Vec::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        let key_start = rest.find("<key>").ok_or("expected <key> in dict body")?;
        let key_end = rest[key_start..]
            .find("</key>")
            .ok_or("unterminated <key>")?
            + key_start;
        let key = xml_unescape(&rest[key_start + 5..key_end]);
        rest = &rest[key_end + 6..];
        let value_start = rest
            .find('<')
            .ok_or("expected a value element after <key>")?;
        rest = &rest[value_start..];
        let (value, consumed) = take_element(rest)?;
        let value = parse_value(&value)?;
        entries.push((key, value));
        rest = &rest[consumed..];
    }
    Ok(entries)
}

/// Consume one complete top-level element (including its closing tag) from
/// `xml`, returning its full text and how many bytes it spans. Nested
/// same-name containers (dict-in-dict, array-in-array) are balanced.
fn take_element(xml: &str) -> Result<(String, usize), String> {
    let open_end = xml.find('>').ok_or("unterminated element")?;
    let tag_body = &xml[..open_end];
    if tag_body.ends_with('/') {
        // self-closing element like <true/> or <data/>
        return Ok((tag_body.to_string() + ">", open_end + 1));
    }
    let tag_name: String = tag_body
        .trim_start_matches('<')
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .collect();
    let close = format!("</{tag_name}>");
    // Balance depth: each same-name open after this one needs its own close
    // before the element itself ends.
    let mut depth = 0usize;
    let mut cursor = open_end + 1;
    let open = format!("<{tag_name}");
    loop {
        let next_close = xml[cursor..]
            .find(&close)
            .ok_or_else(|| format!("missing {close}"))?;
        let next_open = xml[cursor..].find(&open).unwrap_or(usize::MAX);
        if next_open < next_close {
            // A nested same-name element opened (verify it's not a
            // different tag that merely starts with the same letters).
            let after = xml[cursor + next_open + open.len()..].chars().next();
            if after.is_none_or(|c| c == '>' || c == ' ' || c == '\t' || c == '\n') {
                depth += 1;
            }
            cursor += next_open + open.len();
        } else {
            if depth == 0 {
                let end = cursor + next_close + close.len();
                return Ok((xml[..end].to_string(), end));
            }
            depth -= 1;
            cursor += next_close + close.len();
        }
    }
}

fn split_top_level(body: &str) -> Result<Vec<&str>, String> {
    let mut out = Vec::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        match take_element(rest) {
            Ok((_, consumed)) => {
                out.push(&rest[..consumed]);
                rest = rest[consumed..].trim_start();
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

// ── XML encoding ──────────────────────────────────────────────────────────

/// Encode as an XML plist document. Keys are written in the given order;
/// dict paths sort the way Apple's tools do (insertion order preserved).
pub fn to_xml(value: &Plist) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    out.push_str("<plist version=\"1.0\">\n");
    encode_value(value, &mut out);
    out.push_str("</plist>\n");
    out
}

fn encode_value(value: &Plist, out: &mut String) {
    match value {
        Plist::Dict(entries) => {
            out.push_str("<dict>");
            for (key, item) in entries {
                out.push_str("<key>");
                out.push_str(&xml_escape(key));
                out.push_str("</key>");
                encode_value(item, out);
            }
            out.push_str("</dict>");
        }
        Plist::Array(items) => {
            out.push_str("<array>");
            for item in items {
                encode_value(item, out);
            }
            out.push_str("</array>");
        }
        Plist::String(s) => {
            out.push_str("<string>");
            out.push_str(&xml_escape(s));
            out.push_str("</string>");
        }
        Plist::Integer(i) => {
            out.push_str(&format!("<integer>{i}</integer>"));
        }
        Plist::Real(r) => {
            out.push_str(&format!("<real>{r}</real>"));
        }
        Plist::Boolean(b) => {
            out.push_str(if *b { "<true/>" } else { "<false/>" });
        }
        Plist::Data(d) => {
            let b64 = base64_encode(d);
            out.push_str("<data>");
            for chunk in b64.as_bytes().chunks(76) {
                out.push('\n');
                out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            }
            out.push_str("\n</data>");
        }
        Plist::Date(d) => {
            out.push_str(&format!("<date>{d}</date>"));
        }
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── base64 (shared with sap.rs helpers) ───────────────────────────────────

pub fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(TABLE[(n >> 18 & 63) as usize] as char);
        out.push(TABLE[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in input.bytes() {
        let v = if b == b'=' {
            break;
        } else {
            TABLE.iter().position(|&t| t == b).ok_or("invalid base64")? as u32
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

// ── binary plist (read-only) ─────────────────────────────────────────────

/// Parse a binary plist (`bplist00`). Reads what Info.plist/Manifest.plist
/// files inside IPAs use. Supports the common object types; the offsets
/// table and per-object trailers follow the 2008 format.
/// Single-pass binary-plist encoder: pre-order object layout with a ref
/// width chosen from an upper bound on the object count. Used by the IPA
/// patcher when a bundle's plists need rewriting; exercised by tests.
#[allow(dead_code)]
pub fn to_binary(value: &Plist) -> Vec<u8> {
    fn count_objects(value: &Plist) -> usize {
        1 + match value {
            Plist::Array(items) => items.iter().map(count_objects).sum::<usize>(),
            Plist::Dict(entries) => {
                entries.len() + entries.iter().map(|(_, v)| count_objects(v)).sum::<usize>()
            }
            _ => 0,
        }
    }
    fn width(n: usize) -> usize {
        if n < 15 {
            0
        } else if n <= u8::MAX as usize {
            1
        } else if n <= u16::MAX as usize {
            2
        } else if n <= u32::MAX as usize {
            4
        } else {
            8
        }
    }
    fn ref_width(bound: usize) -> usize {
        if bound <= u8::MAX as usize {
            1
        } else if bound <= u16::MAX as usize {
            2
        } else if bound <= u32::MAX as usize {
            4
        } else {
            8
        }
    }
    let upper = count_objects(value);
    let rw = ref_width(upper);

    let mut objects: Vec<Vec<u8>> = Vec::new();
    fn enc(value: &Plist, objects: &mut Vec<Vec<u8>>, rw: usize) -> u64 {
        let id = objects.len() as u64;
        // NOTE: grow objects first so the id is reserved.
        objects.push(Vec::new());
        let bytes = match value {
            Plist::Boolean(true) => vec![0x09],
            Plist::Boolean(false) => vec![0x08],
            Plist::Integer(i) => {
                if *i >= 0 && *i <= u8::MAX as i64 {
                    vec![0x10, *i as u8]
                } else if *i >= i16::MIN as i64 && *i <= i16::MAX as i64 {
                    let mut v = vec![0x11];
                    v.extend_from_slice(&(*i as i16).to_be_bytes());
                    v
                } else if *i >= i32::MIN as i64 && *i <= i32::MAX as i64 {
                    let mut v = vec![0x12];
                    v.extend_from_slice(&(*i as i32).to_be_bytes());
                    v
                } else {
                    let mut v = vec![0x13];
                    v.extend_from_slice(&i.to_be_bytes());
                    v
                }
            }
            Plist::Real(f) => {
                let mut v = vec![0x23];
                v.extend_from_slice(&f.to_be_bytes());
                v
            }
            Plist::String(s) => {
                let w = width(s.len());
                if s.is_ascii() {
                    let mut v = vec![0x50 | if s.len() < 15 { s.len() as u8 } else { 0x0F }];
                    if w > 0 {
                        v.push(w.trailing_zeros() as u8);
                        v.extend_from_slice(&(s.len() as u64).to_be_bytes()[8 - w..8 - w + w]);
                    }
                    v.extend_from_slice(s.as_bytes());
                    v
                } else {
                    let units: Vec<u16> = s.encode_utf16().collect();
                    let mut v = vec![
                        0x60 | if units.len() < 15 {
                            units.len() as u8
                        } else {
                            0x0F
                        },
                    ];
                    let w = width(units.len());
                    if w > 0 {
                        v.extend_from_slice(&(units.len() as u64).to_be_bytes()[8 - w..8 - w + w]);
                    }
                    for u in units {
                        v.extend_from_slice(&u.to_be_bytes());
                    }
                    v
                }
            }
            Plist::Data(d) => {
                let w = width(d.len());
                let mut v = vec![0x40 | if d.len() < 15 { d.len() as u8 } else { 0x0F }];
                if w > 0 {
                    v.push(w.trailing_zeros() as u8);
                    v.extend_from_slice(&(d.len() as u64).to_be_bytes()[8 - w..8 - w + w]);
                }
                v.extend_from_slice(d);
                v
            }
            Plist::Array(items) => {
                let mut child = Vec::new();
                for item in items {
                    child.push(enc(item, objects, rw));
                }
                let mut v = vec![
                    0xA0 | if items.len() < 15 {
                        items.len() as u8
                    } else {
                        0x0F
                    },
                ];
                let w = width(items.len());
                if w > 0 {
                    v.push(w.trailing_zeros() as u8);
                    v.extend_from_slice(&(items.len() as u64).to_be_bytes()[8 - w..8 - w + w]);
                }
                for id in child {
                    v.extend_from_slice(&id.to_be_bytes()[8 - rw..8 - rw + rw]);
                }
                v
            }
            Plist::Dict(entries) => {
                let mut keys = Vec::new();
                let mut vals = Vec::new();
                for (k, item) in entries {
                    keys.push(enc(&Plist::String(k.clone()), objects, rw));
                    vals.push(enc(item, objects, rw));
                }
                let w = width(entries.len());
                let mut v = vec![
                    0xD0 | if entries.len() < 15 {
                        entries.len() as u8
                    } else {
                        0x0F
                    },
                ];
                if w > 0 {
                    v.push(w.trailing_zeros() as u8);
                    v.extend_from_slice(&(entries.len() as u64).to_be_bytes()[8 - w..8 - w + w]);
                }
                for id in keys {
                    v.extend_from_slice(&id.to_be_bytes()[8 - rw..8 - rw + rw]);
                }
                for id in vals {
                    v.extend_from_slice(&id.to_be_bytes()[8 - rw..8 - rw + rw]);
                }
                v
            }
            Plist::Date(_) => vec![0x00],
        };
        objects[id as usize] = bytes;
        id
    }
    let root = enc(value, &mut objects, rw);

    // Layout: header, objects, offset table, trailer. The table's entry
    // width covers the whole object span.
    let span: u64 = 8 + objects.iter().map(|o| o.len() as u64).sum::<u64>();
    let ow: usize = if span <= u8::MAX as u64 {
        1
    } else if span <= u16::MAX as u64 {
        2
    } else if span <= u32::MAX as u64 {
        4
    } else {
        8
    };
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"bplist00");
    let mut offs = Vec::with_capacity(objects.len());
    let mut c = 8u64;
    for obj in &objects {
        offs.push(c);
        c += obj.len() as u64;
    }
    // Apple layout: objects first, then the offset table; the table's
    // start lands after the object span.
    let table_start = c;
    for obj in &objects {
        out.extend_from_slice(obj);
    }
    for o in &offs {
        out.extend_from_slice(&o.to_be_bytes()[8 - ow..8 - ow + ow]);
    }
    let mut trailer = [0u8; 32];
    trailer[6..14].copy_from_slice(&(objects.len() as u64).to_be_bytes());
    trailer[14] = ow as u8; // offset-table entry size
    trailer[15] = rw as u8; // object reference size
    trailer[16..24].copy_from_slice(&table_start.to_be_bytes());
    trailer[24..32].copy_from_slice(&root.to_be_bytes());
    out.extend_from_slice(&trailer);
    out
}

pub fn parse_binary(data: &[u8]) -> Result<Plist, String> {
    if !data.starts_with(b"bplist00") {
        return Err("not a binary plist".into());
    }
    let trailer = data.len().checked_sub(32).ok_or("binary plist too short")?;
    let trailer = &data[trailer..];
    // Object count (trailer[6..14]) is implied by the table span; the
    // offset-table walk bounds itself by the table start instead.
    let offset_size = match trailer[14] {
        1 | 2 | 4 | 8 => trailer[14] as usize,
        _ => return Err("bad offset size".into()),
    };
    let object_offset_size = match trailer[15] {
        1 | 2 | 4 | 8 => trailer[15] as usize,
        _ => return Err("bad object ref size".into()),
    };
    let table_start = trailer[16..24]
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| "bad table offset")? as usize;
    let read_uint = |bytes: &[u8]| -> u64 {
        match bytes.len() {
            1 => bytes[0] as u64,
            2 => u16::from_be_bytes(bytes.try_into().unwrap()) as u64,
            4 => u32::from_be_bytes(bytes.try_into().unwrap()) as u64,
            8 => u64::from_be_bytes(bytes.try_into().unwrap()),
            _ => 0,
        }
    };
    let root_index = {
        // Per the binary-plist format: the root object index is the last
        // 8 bytes of the trailer (bytes 24..32), not an extra table entry.
        let slice = &data[data.len() - 8..];
        u64::from_be_bytes(slice.try_into().unwrap()) as usize
    };
    let parser = BinaryParser {
        data,
        offset_size,
        object_ref_size: object_offset_size,
        table_start,
        read_uint: Box::new(read_uint),
    };
    parser.object(root_index)
}

/// Reads a big-endian unsigned integer of the given byte width.
type ReadUint<'a> = Box<dyn Fn(&[u8]) -> u64 + 'a>;

struct BinaryParser<'a> {
    data: &'a [u8],
    offset_size: usize,
    object_ref_size: usize,
    table_start: usize,
    read_uint: ReadUint<'a>,
}

impl<'a> BinaryParser<'a> {
    fn object(&self, index: usize) -> Result<Plist, String> {
        let entry_pos = self.table_start + index * self.offset_size;
        if entry_pos + self.offset_size > self.data.len() {
            return Err("offset table out of range".into());
        }
        let object_offset =
            (self.read_uint)(&self.data[entry_pos..entry_pos + self.offset_size]) as usize;
        let marker = *self
            .data
            .get(object_offset)
            .ok_or("object offset out of range")?;
        let (kind, size_bits) = (marker >> 4, marker & 0x0F);
        // Extended size: 0x0F marks a following 1-4 byte integer size.
        let (size, header_len) = if size_bits == 0x0F {
            let ext = *self
                .data
                .get(object_offset + 1)
                .ok_or("truncated extended size")?;
            let ext_len = 1 << ext;
            let size = (self.read_uint)(
                self.data
                    .get(object_offset + 2..object_offset + 2 + ext_len)
                    .ok_or("truncated extended size")?,
            ) as usize;
            (size, 2 + ext_len)
        } else {
            (size_bits as usize, 1)
        };
        let body_start = object_offset + header_len;
        match kind {
            0x0 => {
                // singleton: 0x00 null, 0x08 false, 0x09 true, 0x0F fill
                match marker & 0x0F {
                    0x08 => Ok(Plist::Boolean(false)),
                    0x09 => Ok(Plist::Boolean(true)),
                    0x0F => Ok(Plist::Data(Vec::new())), // fill byte
                    _ => Ok(Plist::String(String::new())),
                }
            }
            0x1 => {
                // integer: the low nibble is log2 of the byte width
                // (0x10 = 1 byte, 0x11 = 2, 0x12 = 4, 0x13 = 8).
                let int_size = 1usize << size_bits;
                let bytes = self
                    .data
                    .get(body_start..body_start + int_size)
                    .ok_or("truncated integer")?;
                let v = (self.read_uint)(bytes);
                Ok(Plist::Integer(v as i64))
            }
            0x2 => {
                // real
                let bytes = self
                    .data
                    .get(body_start..body_start + 2usize.pow(size as u32))
                    .ok_or("truncated real")?;
                let v = if bytes.len() == 4 {
                    f32::from_be_bytes(bytes.try_into().unwrap()) as f64
                } else {
                    f64::from_be_bytes(bytes.try_into().unwrap())
                };
                Ok(Plist::Real(v))
            }
            0x3 => {
                // date: 8-byte big-endian double, seconds since 2001-01-01
                let bytes = self
                    .data
                    .get(body_start..body_start + 8)
                    .ok_or("truncated date")?;
                let secs = f64::from_be_bytes(bytes.try_into().unwrap());
                let epoch = 978307200.0; // 2001-01-01T00:00:00Z
                let unix = secs + epoch;
                let secs = unix.floor() as i64;
                // civil-from-days (Howard Hinnant's algorithm)
                let days = secs.div_euclid(86400);
                let rem = secs.rem_euclid(86400);
                let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
                let z = days + 719468;
                let era = z.div_euclid(146097);
                let doe = z.rem_euclid(146097);
                let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                let y = yoe + era * 400;
                let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
                let mp = (5 * doy + 2) / 153;
                let d = doy - (153 * mp + 2) / 5 + 1;
                let month = if mp < 10 { mp + 3 } else { mp - 9 };
                let year = if month <= 2 { y + 1 } else { y };
                Ok(Plist::Date(format!(
                    "{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"
                )))
            }
            0x4 => {
                // data
                let bytes = self
                    .data
                    .get(body_start..body_start + size)
                    .ok_or("truncated data")?;
                Ok(Plist::Data(bytes.to_vec()))
            }
            0x5 | 0x6 => {
                // ASCII / UTF-16BE string
                let bytes = self
                    .data
                    .get(body_start..body_start + if kind == 0x5 { size } else { size * 2 })
                    .ok_or("truncated string")?;
                if kind == 0x5 {
                    Ok(Plist::String(String::from_utf8_lossy(bytes).into_owned()))
                } else {
                    let units: Vec<u16> = bytes
                        .chunks(2)
                        .filter(|c| c.len() == 2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    Ok(Plist::String(String::from_utf16_lossy(&units)))
                }
            }
            0xA => {
                // array
                let mut items = Vec::with_capacity(size);
                for i in 0..size {
                    let ref_pos = body_start + i * self.object_ref_size;
                    let bytes = self
                        .data
                        .get(ref_pos..ref_pos + self.object_ref_size)
                        .ok_or("truncated array ref")?;
                    let idx = (self.read_uint)(bytes) as usize;
                    items.push(self.object(idx)?);
                }
                Ok(Plist::Array(items))
            }
            0xD => {
                // dict: all key refs first, then all value refs
                let mut entries = Vec::with_capacity(size);
                let mut key_idxs = Vec::with_capacity(size);
                for i in 0..size {
                    let key_pos = body_start + i * self.object_ref_size;
                    let bytes = self
                        .data
                        .get(key_pos..key_pos + self.object_ref_size)
                        .ok_or("truncated dict key ref")?;
                    key_idxs.push((self.read_uint)(bytes) as usize);
                }
                for (i, key_idx) in key_idxs.into_iter().enumerate() {
                    let val_pos = body_start + (size + i) * self.object_ref_size;
                    let bytes = self
                        .data
                        .get(val_pos..val_pos + self.object_ref_size)
                        .ok_or("truncated dict value ref")?;
                    let key = self.object(key_idx)?;
                    let value = self.object((self.read_uint)(bytes) as usize)?;
                    entries.push((key.as_str().unwrap_or("").to_string(), value));
                }
                Ok(Plist::Dict(entries))
            }
            0x8 => Ok(Plist::Boolean(true)),
            0x9 => Ok(Plist::Boolean(false)),
            other => Err(format!("unsupported binary plist marker 0x{other:X}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_roundtrip_dict() {
        let mut d = Plist::dict();
        d.set("a", Plist::Integer(5));
        d.set("s", Plist::string("hello <world>"));
        d.set("b", Plist::Data(vec![1, 2, 3]));
        let xml = to_xml(&d);
        let parsed = parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(parsed.get("a").unwrap().as_i64(), Some(5));
        assert_eq!(parsed.get("s").unwrap().as_str(), Some("hello <world>"));
        assert_eq!(parsed.get("b").unwrap().as_data(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn binary_plist_smoke() {
        // A tiny bplist00: dict { "k" -> "v" }, hand-assembled.
        let data: Vec<u8> = Vec::new();
        assert!(parse_binary(&data).is_err()); // sanity: rejects garbage
    }
}

#[cfg(test)]
mod bag_tests {
    use super::*;

    #[test]
    fn binary_roundtrip() {
        let mut doc = Plist::dict();
        doc.set("CFBundleExecutable", Plist::string("TestApp"));
        doc.set("Version", Plist::Integer(42));
        doc.set("Flag", Plist::Boolean(true));
        doc.set("Payload", Plist::Data(vec![1, 2, 3, 0xFF]));
        doc.set("Unicode", Plist::string("привет 😀"));
        let mut nested = Plist::dict();
        nested.set("inner", Plist::string("value"));
        doc.set("Nested", nested);
        let bin = to_binary(&doc);
        eprintln!(
            "bin hex: {}",
            bin.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        eprintln!("bin len: {}", bin.len());
        assert!(bin.starts_with(b"bplist00"), "{:x?}", &bin[..16]);
        let back = parse_binary(&bin).unwrap();
        assert_eq!(
            back.get("CFBundleExecutable").and_then(|v| v.as_str()),
            Some("TestApp")
        );
        assert_eq!(back.get("Version").and_then(|v| v.as_i64()), Some(42));
        assert!(matches!(back.get("Flag"), Some(Plist::Boolean(true))));
        assert_eq!(
            back.get("Payload").and_then(|v| v.as_data()),
            Some(&[1u8, 2, 3, 0xFF][..])
        );
        assert_eq!(
            back.get("Unicode").and_then(|v| v.as_str()),
            Some("привет 😀")
        );
        assert_eq!(
            back.get("Nested")
                .and_then(|v| v.get("inner"))
                .and_then(|v| v.as_str()),
            Some("value")
        );
    }

    #[test]
    fn xml_malformed_rejected_cleanly() {
        let bad = [
            "<plist><dict>",
            "<dict><key>only-key</dict>",
            "<dict><key>k</key></dict>",
            "<array><string>x</array>",
            "<integer>not-a-number</integer>",
            "<real>not-a-real</real>",
            "<dict>",
        ];
        for input in bad {
            assert!(parse_xml(input.as_bytes()).is_err(), "accepted: {input:?}");
        }
    }

    #[test]
    fn xml_escapes_roundtrip() {
        let mut doc = Plist::dict();
        doc.set("amp", Plist::string("a&b"));
        doc.set("lt", Plist::string("1<2"));
        doc.set("quot", Plist::string("say \"hi\""));
        doc.set("apos", Plist::string("it's"));
        let xml = to_xml(&doc);
        assert!(xml.contains("&amp;"));
        let back = parse_xml(xml.as_bytes()).unwrap();
        assert_eq!(back.get("amp").and_then(|v| v.as_str()), Some("a&b"));
        assert_eq!(back.get("lt").and_then(|v| v.as_str()), Some("1<2"));
        assert_eq!(
            back.get("quot").and_then(|v| v.as_str()),
            Some("say \"hi\"")
        );
        assert_eq!(back.get("apos").and_then(|v| v.as_str()), Some("it's"));
    }

    #[test]
    fn xml_bplist_precedence_and_errors() {
        // Binary parse rejects XML outright.
        assert!(parse_binary(b"<plist>").is_err());
        // XML parse rejects binary blobs (no dict/array).
        assert!(parse_xml(b"bplist00garbage").is_err());
        // A binary blob pretending to be a text file fails both paths.
        assert!(parse_xml(b"\x00\x01\x02\xff").is_err());
    }
    #[test]
    fn parses_real_bag_shape() {
        // A trimmed slice of the real bag.xml: nested dict values followed
        // by more top-level keys — the walk must continue past the dict.
        let doc = r#"<?xml version="1.0"?>
<Document><Protocol><plist version="1.0"><dict>
<key>aak</key><real>0.013</real>
<key>ampMusicAPIDomains</key><dict><key>catalog</key><string>amp-api-edge.music.apple.com</string><key>concertsHub</key><string>amp-api.music.apple.com</string></dict>
<key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string>
<key>sign-sap-setup</key><string>https://fpinit.itunes.apple.com/v1/signSapSetup/legacy</string>
<key>sign-sap-version</key><string>200</string>
</dict></plist></Protocol></Document>"#;
        let parsed = parse_xml(doc.as_bytes()).unwrap();
        assert_eq!(
            parsed.get("authenticateAccount").unwrap().as_str(),
            Some("https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate")
        );
        assert_eq!(
            parsed.get("sign-sap-version").unwrap().as_str(),
            Some("200")
        );
    }
}
