//! Both ends of one mDNS exchange on this machine (ADR-0051): a browser at
//! an ephemeral local port, and a responder that announces a service to it
//! and holds the Stream. mDNS says what a device offers rather than what it
//! sends, and a Stream arrives as what it says it in: the browser queries
//! for the Stream chunk by chunk, each the instance `chunk-N` of one
//! service type, and the responder answers each query with that instance's
//! records, its TXT strings [`STRING`] bytes in hex each; a query past the
//! end is answered with no strings, and that closes it. Every chunk is
//! asked for: announcing them unasked lost the tail of a mebibyte on
//! loopback (2026-09-09), because nobody acknowledges an announcement and
//! the socket buffer was the only flow control there was.

use std::fmt::Write;
use std::net::UdpSocket;

use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;

use crate::message::{self, MAX_MESSAGE, Message};
use crate::{MdnsTransport, Service, TTL};

/// What one TXT string carries: twice this in hex fits the 255 bytes a
/// string holds.
const STRING: usize = 125;
/// What one response carries: this many strings and the three records
/// stay inside the message mDNS sends.
const CHUNK: usize = STRING * 32;
/// The service type every chunk is an instance of, instance `chunk-N`.
const KIND: &str = "_xmip._udp";
/// The instance the responder announces itself as.
const INSTANCE: &str = "stream";

impl MdnsTransport {
    /// Both ends on this machine: a browser at an ephemeral local port,
    /// the loopback timeout on both.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }

    /// The service `instance` of [`KIND`] on this host, its TXT being
    /// `txt`.
    fn service(&self, instance: &str, txt: Vec<String>) -> Service {
        Service {
            instance: instance.to_string(),
            kind: KIND.to_string(),
            port: 1,
            txt,
            host: self.host.clone(),
            addresses: self.addresses.clone(),
        }
    }
}

/// A bound browser waiting for a responder to announce itself.
struct Browser {
    transport: MdnsTransport,
    socket: UdpSocket,
    address: String,
}

impl FarEnd for Browser {
    fn address(&self) -> &str {
        &self.address
    }

    /// Take the announcement, then query the responder that made it for
    /// the Stream, a chunk per query.
    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let announced = self
            .transport
            .receive_datagram(&self.socket)?
            .into_iter()
            .next()
            .ok_or_else(|| protocol_error("an announcement naming no service"))?;
        let responder = peer_of(&announced.origin_uri)?;
        let mut bytes = Vec::new();
        for n in 0..usize::MAX {
            let name = format!("chunk-{n}.{KIND}.local.");
            let query = Message::query(&name, message::TYPE_ANY);
            self.socket
                .send_to(&message::encode(&query)?, &responder)
                .map_err(|e| classify("querying", &e))?;
            for arrived in self.transport.receive_datagram(&self.socket)? {
                if arrived.bytes.is_empty() {
                    return Ok(Arrived::new(announced.origin_uri, bytes));
                }
                let text = std::str::from_utf8(&arrived.bytes)
                    .map_err(|_| protocol_error("TXT strings that are not text"))?;
                for line in text.lines() {
                    bytes.extend(unhex(line)?);
                }
            }
        }
        Err(protocol_error("a Stream that never ends"))
    }
}

impl Loopback for MdnsTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (socket, address) = self.bind_udp()?;
        Ok(Box::new(Browser {
            transport: self.clone(),
            socket,
            address,
        }))
    }

    /// A responder announces a service to the browser at `address`, then
    /// answers its queries until one asks past the end.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let (responder, _) = socket::bind_udp("127.0.0.1:0", self.timeout)?;
        let records = self.service(INSTANCE, Vec::new()).records(TTL);
        responder
            .send_to(&message::encode(&Message::response(0, records))?, address)
            .map_err(|e| classify("announcing", &e))?;
        let chunks = payload.chunks(CHUNK).count();
        let mut buffer = vec![0u8; MAX_MESSAGE];
        loop {
            let (read, peer) = responder
                .recv_from(&mut buffer)
                .map_err(|e| classify("awaiting a query", &e))?;
            let query = message::decode(&buffer[..read])?;
            let asked = query.questions.first().map_or("", |q| q.name.as_str());
            let n = chunk_asked(asked)?;
            let txt = payload
                .chunks(CHUNK)
                .nth(n)
                .map(|chunk| chunk.chunks(STRING).map(hex).collect())
                .unwrap_or_default();
            let records = self.service(&format!("chunk-{n}"), txt).records(TTL);
            let response = Message::response(query.id, records);
            responder
                .send_to(&message::encode(&response)?, peer)
                .map_err(|e| classify("answering a query", &e))?;
            if n >= chunks {
                return Ok(());
            }
        }
    }

    fn unblock(&self, _address: &str) {
        // The receive has its own timeout; there is no listener to poke.
    }
}

/// The peer an origin `mdns://peer/…` names.
fn peer_of(origin: &str) -> Result<String> {
    socket::target("mdns", origin)
        .map(|(authority, _)| authority)
        .filter(|peer| !peer.is_empty())
        .map(str::to_string)
        .ok_or_else(|| protocol_error(format!("an origin naming no peer: {origin}")))
}

/// The chunk a query name asks for, `chunk-N.…`, where it asks for one.
fn chunk_asked(name: &str) -> Result<usize> {
    name.strip_prefix("chunk-")
        .and_then(|rest| rest.split('.').next()?.parse().ok())
        .ok_or_else(|| protocol_error(format!("a query for something else: {name:?}")))
}

/// `bytes` as lower-case hex pairs, the form a TXT string takes.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes `digits` spell, refused where they do not.
fn unhex(digits: &str) -> Result<Vec<u8>> {
    if !digits.len().is_multiple_of(2) {
        return Err(protocol_error(format!(
            "an odd number of hex digits: {digits:?}"
        )));
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| {
            digits
                .get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| protocol_error(format!("not hex: {digits:?}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reads_back_and_a_query_names_its_chunk() {
        assert_eq!(hex(&[0, 0x7f, 0xff]), "007fff");
        assert_eq!(unhex("007fff").expect("hex"), [0, 0x7f, 0xff]);
        assert!(unhex("").expect("nothing").is_empty());
        assert!(unhex("abc").is_err(), "odd");
        assert!(unhex("zz").is_err(), "not hex");
        assert_eq!(
            chunk_asked("chunk-12._xmip._udp.local.").expect("asked"),
            12
        );
        assert!(chunk_asked("_ipp._tcp.local.").is_err());
        assert_eq!(
            peer_of("mdns://127.0.0.1:5353/stream._xmip._udp.local?port=1&host=xmip.local.")
                .expect("peer"),
            "127.0.0.1:5353"
        );
        assert!(peer_of("mdns:///x").is_err());
        assert!(peer_of("http://127.0.0.1:5353/x").is_err());
    }
}
