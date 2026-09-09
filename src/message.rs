//! RFC 6762 section 18 over RFC 1035 section 4: the DNS message as
//! multicast DNS uses it. Compact on purpose — the header, questions and
//! the five record types DNS-SD is made of (PTR, SRV, TXT, A, AAAA), name
//! compression followed on read and never written, and the two bits mDNS
//! borrows: the QU bit on a question's class and the cache-flush bit on a
//! record's. Its own codec so this technology stands without the dns one,
//! which speaks dynamic update and nothing here.

use std::net::{Ipv4Addr, Ipv6Addr};

use transport::error::{Result, protocol_error};

/// The largest message mDNS sends, RFC 6762 section 17.
pub const MAX_MESSAGE: usize = 9000;

pub const TYPE_A: u16 = 1;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_ANY: u16 = 255;
pub const CLASS_IN: u16 = 1;
/// The QU bit of a question, and the cache-flush bit of a record.
pub const BIT_UNICAST: u16 = 0x8000;
pub const FLAG_RESPONSE: u16 = 0x8000;
pub const FLAG_AUTHORITATIVE: u16 = 0x0400;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
    /// `CLASS_IN`, with [`BIT_UNICAST`] where a unicast answer is asked for.
    pub class: u16,
}

/// What a record carries, by type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordData {
    Ptr(String),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// The character strings, each at most 255 bytes.
    Txt(Vec<String>),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// Any other type, as it came.
    Other(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    /// `CLASS_IN`, with [`BIT_UNICAST`] where the record replaces the cache.
    pub class: u16,
    pub ttl: u32,
    pub data: RecordData,
}

/// One message, its four sections by their RFC 1035 names.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Message {
    pub id: u16,
    pub flags: u16,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    pub additional: Vec<Record>,
}

impl Message {
    /// A query for `kind` records at `name`, id 0 as mDNS queries carry.
    #[must_use]
    pub fn query(name: &str, kind: u16) -> Self {
        Self {
            questions: vec![Question {
                name: name.to_string(),
                kind,
                class: CLASS_IN,
            }],
            ..Self::default()
        }
    }

    /// An authoritative response carrying `answers`, unsolicited — an
    /// announcement — when `id` is 0.
    #[must_use]
    pub fn response(id: u16, answers: Vec<Record>) -> Self {
        Self {
            id,
            flags: FLAG_RESPONSE | FLAG_AUTHORITATIVE,
            answers,
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & FLAG_RESPONSE != 0
    }

    /// Every record in every section, in order.
    pub fn records(&self) -> impl Iterator<Item = &Record> + Clone {
        self.answers
            .iter()
            .chain(&self.authority)
            .chain(&self.additional)
    }
}

/// Encode `message`. Names are written whole.
///
/// # Errors
/// A label over 63 bytes, a TXT string over 255, rdata over 65535, or a
/// message over [`MAX_MESSAGE`].
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for value in [message.id, message.flags] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    for section in [
        message.questions.len(),
        message.answers.len(),
        message.authority.len(),
        message.additional.len(),
    ] {
        let count = u16::try_from(section).map_err(|_| protocol_error("a section too long"))?;
        out.extend_from_slice(&count.to_be_bytes());
    }
    for question in &message.questions {
        name(&mut out, &question.name)?;
        out.extend_from_slice(&question.kind.to_be_bytes());
        out.extend_from_slice(&question.class.to_be_bytes());
    }
    for record in message.records() {
        name(&mut out, &record.name)?;
        out.extend_from_slice(&record.kind.to_be_bytes());
        out.extend_from_slice(&record.class.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let rdata = rdata(&record.data)?;
        let length = u16::try_from(rdata.len())
            .map_err(|_| protocol_error("rdata over what a record carries"))?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    if out.len() > MAX_MESSAGE {
        return Err(protocol_error("a message over what mDNS sends"));
    }
    Ok(out)
}

fn rdata(data: &RecordData) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    match data {
        RecordData::Ptr(target) => name(&mut out, target)?,
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for value in [priority, weight, port] {
                out.extend_from_slice(&value.to_be_bytes());
            }
            name(&mut out, target)?;
        }
        RecordData::Txt(strings) => {
            for string in strings {
                let length = u8::try_from(string.len())
                    .map_err(|_| protocol_error("a TXT string over 255 bytes"))?;
                out.push(length);
                out.extend_from_slice(string.as_bytes());
            }
            if strings.is_empty() {
                out.push(0);
            }
        }
        RecordData::A(address) => out.extend_from_slice(&address.octets()),
        RecordData::Aaaa(address) => out.extend_from_slice(&address.octets()),
        RecordData::Other(bytes) => out.extend_from_slice(bytes),
    }
    Ok(out)
}

fn name(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let mut total = 0;
    for label in text.split('.').filter(|l| !l.is_empty()) {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|l| *l <= 63)
            .ok_or_else(|| protocol_error(format!("{label:?} is longer than a label may be")))?;
        total += usize::from(length) + 1;
        out.push(length);
        out.extend_from_slice(label.as_bytes());
    }
    if total > 254 {
        return Err(protocol_error("a name over 255 bytes"));
    }
    out.push(0);
    Ok(())
}

/// Decode one message.
///
/// # Errors
/// Shorter than its header, a section shorter than its count, a
/// compression pointer that loops or points forward, a label over 63, or
/// rdata of a known type that is not shaped as that type.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 12 {
        return Err(protocol_error("a message shorter than its header"));
    }
    let counts = [
        field16(bytes, 4)?,
        field16(bytes, 6)?,
        field16(bytes, 8)?,
        field16(bytes, 10)?,
    ];
    let mut at = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (text, next) = read_name(bytes, at)?;
        questions.push(Question {
            name: text,
            kind: field16(bytes, next)?,
            class: field16(bytes, next + 2)?,
        });
        at = next + 4;
    }
    let mut sections: [Vec<Record>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (section, count) in sections.iter_mut().zip(&counts[1..]) {
        for _ in 0..*count {
            let (record, next) = read_record(bytes, at)?;
            section.push(record);
            at = next;
        }
    }
    let [answers, authority, additional] = sections;
    Ok(Message {
        id: field16(bytes, 0)?,
        flags: field16(bytes, 2)?,
        questions,
        answers,
        authority,
        additional,
    })
}

fn read_record(bytes: &[u8], at: usize) -> Result<(Record, usize)> {
    let (text, next) = read_name(bytes, at)?;
    let kind = field16(bytes, next)?;
    let class = field16(bytes, next + 2)?;
    let ttl = u32::from(field16(bytes, next + 4)?) << 16 | u32::from(field16(bytes, next + 6)?);
    let length = usize::from(field16(bytes, next + 8)?);
    let start = next + 10;
    let raw = bytes.get(start..start + length).ok_or_else(short)?;
    let data = match kind {
        TYPE_PTR => RecordData::Ptr(read_name(bytes, start)?.0),
        TYPE_SRV => RecordData::Srv {
            priority: field16(raw, 0)?,
            weight: field16(raw, 2)?,
            port: field16(raw, 4)?,
            target: read_name(bytes, start + 6)?.0,
        },
        TYPE_TXT => RecordData::Txt(read_strings(raw)?),
        TYPE_A => {
            let octets: [u8; 4] = raw
                .try_into()
                .map_err(|_| protocol_error("an A record that is not four bytes"))?;
            RecordData::A(Ipv4Addr::from(octets))
        }
        TYPE_AAAA => {
            let octets: [u8; 16] = raw
                .try_into()
                .map_err(|_| protocol_error("an AAAA record that is not sixteen bytes"))?;
            RecordData::Aaaa(Ipv6Addr::from(octets))
        }
        _ => RecordData::Other(raw.to_vec()),
    };
    Ok((
        Record {
            name: text,
            kind,
            class,
            ttl,
            data,
        },
        start + length,
    ))
}

fn read_strings(raw: &[u8]) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    let mut at = 0;
    while at < raw.len() {
        let length = usize::from(raw[at]);
        let string = raw
            .get(at + 1..at + 1 + length)
            .ok_or_else(|| protocol_error("a TXT string shorter than its length"))?;
        if !string.is_empty() {
            strings.push(String::from_utf8_lossy(string).into_owned());
        }
        at += 1 + length;
    }
    Ok(strings)
}

fn short() -> transport::TransportError {
    protocol_error("a section shorter than its count")
}

fn field16(bytes: &[u8], at: usize) -> Result<u16> {
    let pair = bytes.get(at..at + 2).ok_or_else(short)?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

/// A name at `at`, pointers followed; the name with its trailing dot and
/// where the next field starts.
fn read_name(bytes: &[u8], at: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = at;
    let mut next = None;
    let mut hops = 0;
    loop {
        let length = *bytes.get(cursor).ok_or_else(short)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(cursor + 1).ok_or_else(short)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if pointer >= cursor || hops > 32 {
                return Err(protocol_error("a compression pointer that loops"));
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            hops += 1;
            continue;
        }
        if length > 63 {
            return Err(protocol_error("a label over 63 bytes"));
        }
        cursor += 1;
        if length == 0 {
            break;
        }
        let label = bytes
            .get(cursor..cursor + usize::from(length))
            .ok_or_else(short)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor += usize::from(length);
    }
    let mut text = labels.join(".");
    if !text.is_empty() {
        text.push('.');
    }
    Ok((text, next.unwrap_or(cursor)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, kind: u16, data: RecordData) -> Record {
        Record {
            name: name.to_string(),
            kind,
            class: CLASS_IN | BIT_UNICAST,
            ttl: 120,
            data,
        }
    }

    #[test]
    fn a_service_response_round_trips() {
        let response = Message::response(
            0,
            vec![
                record(
                    "_ipp._tcp.local.",
                    TYPE_PTR,
                    RecordData::Ptr("Printer._ipp._tcp.local.".into()),
                ),
                record(
                    "Printer._ipp._tcp.local.",
                    TYPE_SRV,
                    RecordData::Srv {
                        priority: 0,
                        weight: 0,
                        port: 631,
                        target: "printer.local.".into(),
                    },
                ),
                record(
                    "Printer._ipp._tcp.local.",
                    TYPE_TXT,
                    RecordData::Txt(vec!["txtvers=1".into(), "rp=ipp/print".into()]),
                ),
                record(
                    "printer.local.",
                    TYPE_A,
                    RecordData::A(Ipv4Addr::new(10, 0, 0, 5)),
                ),
                record(
                    "printer.local.",
                    TYPE_AAAA,
                    RecordData::Aaaa(Ipv6Addr::LOCALHOST),
                ),
                record("printer.local.", 47, RecordData::Other(vec![1, 2, 3])),
            ],
        );
        let bytes = encode(&response).expect("encode");
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, response);
        assert!(back.is_response());
        assert_eq!(back.records().count(), 6);
        let query = Message::query("_ipp._tcp.local.", TYPE_PTR);
        let back = decode(&encode(&query).expect("encode")).expect("decode");
        assert_eq!(back, query);
        assert!(!back.is_response());
        let empty_txt = Message::response(1, vec![record("n.", TYPE_TXT, RecordData::Txt(vec![]))]);
        let back = decode(&encode(&empty_txt).expect("encode")).expect("decode");
        assert_eq!(back.answers[0].data, RecordData::Txt(vec![]));
    }

    #[test]
    fn compression_is_followed_in_names_and_rdata_and_bad_shapes_refused() {
        // A question for a.b., a PTR answer whose name and target point at it.
        let mut bytes = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        bytes.extend_from_slice(&[1, b'a', 1, b'b', 0, 0, 12, 0, 1]);
        bytes.extend_from_slice(&[0xc0, 12, 0, 12, 0, 1, 0, 0, 0, 5, 0, 4, 1, b'x', 0xc0, 12]);
        let message = decode(&bytes).expect("decode");
        assert_eq!(message.answers[0].name, "a.b.");
        assert_eq!(message.answers[0].data, RecordData::Ptr("x.a.b.".into()));
        let mut looping = bytes.clone();
        looping[21] = 21;
        assert!(decode(&looping).is_err(), "pointer at itself");
        assert!(decode(&bytes[..11]).is_err(), "short header");
        assert!(decode(&bytes[..25]).is_err(), "short section");
        let short_a = Message::response(0, vec![record("n.", TYPE_A, RecordData::Other(vec![1]))]);
        assert!(
            decode(&encode(&short_a).expect("encode")).is_err(),
            "A of one byte"
        );
        let bad_txt = Message::response(
            0,
            vec![record("n.", TYPE_TXT, RecordData::Other(vec![5, b'a']))],
        );
        assert!(
            decode(&encode(&bad_txt).expect("encode")).is_err(),
            "TXT string cut"
        );
        let long_label = "x".repeat(64);
        assert!(encode(&Message::query(&long_label, TYPE_PTR)).is_err());
        let long_txt = RecordData::Txt(vec!["y".repeat(256)]);
        assert!(
            encode(&Message::response(
                0,
                vec![record("n.", TYPE_TXT, long_txt)]
            ))
            .is_err()
        );
        let huge = RecordData::Other(vec![0; 70_000]);
        assert!(encode(&Message::response(0, vec![record("n.", 47, huge)])).is_err());
    }
}
