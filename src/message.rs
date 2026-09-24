//! RFC 6762 section 18: multicast DNS is the DNS message of RFC 1035
//! section 4 with two bits repurposed, and its codec is the dns
//! technology's (`dns::message`), which reads the QU and cache-flush bit
//! as [`BIT_UNICAST`](dns::record::BIT_UNICAST). What is mDNS's own is
//! the size it sends.

use dns::message::{self, Message};
use transport::error::{Result, protocol_error};

/// The largest message mDNS sends, RFC 6762 section 17.
pub const MAX_MESSAGE: usize = 9000;

/// Encode `message` as mDNS sends it.
///
/// # Errors
/// What [`dns::message::encode`] refuses, or a message over
/// [`MAX_MESSAGE`].
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    let bytes = message::encode(message)?;
    if bytes.len() > MAX_MESSAGE {
        return Err(protocol_error("a message over what mDNS sends"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns::record::{CLASS_IN, Record, RecordData};

    #[test]
    fn a_message_over_what_mdns_sends_is_refused() {
        let record = |bytes: usize| Record {
            name: "n.local.".into(),
            kind: 47,
            class: CLASS_IN,
            ttl: 120,
            data: RecordData::Other(vec![0; bytes]),
        };
        let fits = Message::authoritative(0, vec![record(8000)]);
        assert!(encode(&fits).is_ok());
        let over = Message::authoritative(0, vec![record(9000)]);
        assert!(encode(&over).is_err());
        assert!(message::encode(&over).is_ok(), "DNS itself frames it");
    }
}
