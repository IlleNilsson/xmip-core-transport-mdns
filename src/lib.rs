#![forbid(unsafe_code)]

//! Streams that arrive as mDNS service records. One service instance
//! found is one Stream: its TXT strings, one `key=value` line each, with
//! the instance, kind, port and host in the origin.
//!
//! Multicast DNS (RFC 6762) with DNS-SD (RFC 6763) is how devices on a
//! link say what they offer without a server: a printer announces
//! `Printer._ipp._tcp.local.` on port 631 with its TXT strings, and a
//! browser asks for `_ipp._tcp.local.` and takes the answers. A Receive
//! Location joins the group and takes what is announced — or, built
//! `browsing(kind)`, asks first and takes the answers; a Send Location
//! announces a service of its own.
//!
//! The origin URI carries what the records knew:
//! `mdns://peer/Printer._ipp._tcp.local?port=631&host=printer.local.`.
//!
//! A send goes to `mdns://host:port/<instance>.<kind>.local?port=8080`,
//! the group being `mdns://224.0.0.251:5353`; the bytes are the TXT
//! strings, one per line. A bare `host:port` has no service in it and is
//! refused.
//!
//! Multicast is joined when the bind address is in 224/4 — the socket
//! binds the port on every interface and joins the group — and is never
//! used under test; a test binds `127.0.0.1:0` and answers from a second
//! socket.

pub mod message;
pub mod service;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub use message::{MAX_MESSAGE, Message, Record, RecordData};
pub use service::Service;
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

/// The multicast group and port mDNS lives on.
pub const GROUP: &str = "224.0.0.251:5353";
/// How long an announced record lives, RFC 6762 section 10.
pub const TTL: u32 = 120;

pub struct MdnsTransport {
    bind: String,
    group: String,
    browsing: Option<String>,
    host: String,
    addresses: Vec<IpAddr>,
    timeout: Option<Duration>,
}

impl MdnsTransport {
    /// Listen at `bind`: the group `224.0.0.251:5353` for what the link
    /// announces, or a unicast address for answers to its own query.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            group: GROUP.to_string(),
            browsing: None,
            host: "xmip.local.".to_string(),
            addresses: Vec::new(),
            timeout: None,
        }
    }

    /// Ask for `kind` — `_ipp._tcp` — before taking answers.
    #[must_use]
    pub fn browsing(mut self, kind: &str) -> Self {
        self.browsing = Some(kind.trim_end_matches('.').to_string());
        self
    }

    /// Where a query goes; the group unless a test says otherwise.
    #[must_use]
    pub fn asking(mut self, address: &str) -> Self {
        self.group = address.to_string();
        self
    }

    /// The host an announced service runs on — `gateway`, placed in
    /// `local.` unless already there — and its addresses.
    #[must_use]
    pub fn as_host(mut self, host: &str, addresses: &[IpAddr]) -> Self {
        let host = host.trim_end_matches('.');
        self.host = if host.to_ascii_lowercase().ends_with(".local") {
            format!("{host}.")
        } else {
            format!("{host}.{}", service::DOMAIN)
        };
        self.addresses = addresses.to_vec();
        self
    }

    /// Give up waiting for a message after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the UDP socket, joining the group when the bind address is a
    /// multicast one, and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted, or the
    /// group could not be joined.
    pub fn bind_udp(&self) -> Result<(UdpSocket, String)> {
        let Some((group, port)) = multicast_group(&self.bind) else {
            return socket::bind_udp(&self.bind, self.timeout);
        };
        let (socket, local) = socket::bind_udp(&port, self.timeout)?;
        socket
            .join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)
            .map_err(|e| classify("joining the group", &e))?;
        Ok((socket, local))
    }

    /// Send the query for the kind being browsed, where there is one.
    ///
    /// # Errors
    /// Where the query could not be sent.
    pub fn query(&self, socket: &UdpSocket) -> Result<()> {
        let Some(kind) = &self.browsing else {
            return Ok(());
        };
        let query = Message::query(&format!("{kind}.{}", service::DOMAIN), message::TYPE_PTR);
        socket
            .send_to(&message::encode(&query)?, &self.group)
            .map_err(|e| classify("sending the query", &e))?;
        Ok(())
    }

    /// Take the services one response names, from an already-bound socket.
    /// A query arriving is skipped, as is a response naming no service.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not DNS.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Vec<Arrived>> {
        let mut buffer = vec![0u8; MAX_MESSAGE];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .map_err(|e| classify("receiving a datagram", &e))?;
            let message = message::decode(&buffer[..read])?;
            if !message.is_response() {
                continue;
            }
            let found: Vec<Arrived> = Service::from_records(message.records())
                .iter()
                .map(|service| arrived(peer, service))
                .collect();
            if !found.is_empty() {
                return Ok(found);
            }
        }
    }

    /// The service `target` names, its TXT strings being `bytes`.
    ///
    /// # Errors
    /// A target without `/<instance>.<kind>.local`, or without a port.
    pub fn service_at(&self, target: &str) -> Result<(String, Service)> {
        let Some((address, path)) = socket::target("mdns", target) else {
            return Err(protocol_error(format!(
                "an mdns target names the service: mdns://host:port/<instance>.<kind>.local?port=…, got {target}"
            )));
        };
        let (name, query) = path.split_once('?').unwrap_or((path, ""));
        let name = format!("{}.", name.trim_end_matches('.'));
        let (instance, kind) = Service::split_name(&name)
            .ok_or_else(|| protocol_error(format!("not <instance>.<kind>.local: {name}")))?;
        let port = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("port=")?.parse().ok())
            .ok_or_else(|| protocol_error(format!("a service without ?port=: {target}")))?;
        Ok((
            address.to_string(),
            Service {
                instance,
                kind,
                port,
                txt: Vec::new(),
                host: self.host.clone(),
                addresses: self.addresses.clone(),
            },
        ))
    }
}

/// The group and the `0.0.0.0:port` to bind for it, where `bind` is a
/// multicast address.
#[must_use]
pub fn multicast_group(bind: &str) -> Option<(Ipv4Addr, String)> {
    let address: SocketAddrV4 = bind.parse().ok()?;
    address
        .ip()
        .is_multicast()
        .then(|| (*address.ip(), format!("0.0.0.0:{}", address.port())))
}

fn arrived(peer: SocketAddr, service: &Service) -> Arrived {
    Arrived::new(
        format!(
            "mdns://{peer}/{}?port={}&host={}",
            service.full_name().trim_end_matches('.'),
            service.port,
            service.host
        ),
        service.txt_lines(),
    )
}

impl Transport for MdnsTransport {
    fn name(&self) -> &'static str {
        "mdns"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (socket, _) = self.bind_udp()?;
        self.query(&socket)?;
        self.receive_datagram(&socket)
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, mut service) = self.service_at(target)?;
        service.txt = Service::parse_txt(bytes);
        let announcement = Message::response(0, service.records(TTL));
        let sender =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| classify("binding the sending socket", &e))?;
        sender
            .send_to(&message::encode(&announcement)?, address)
            .map_err(|e| classify("sending the announcement", &e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> MdnsTransport {
        MdnsTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2))
    }

    #[test]
    fn an_announcement_arrives_as_its_txt_with_the_service_in_the_origin() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        node()
            .as_host("gateway", &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))])
            .send(
                &format!("mdns://{address}/Gateway._xmip._tcp.local?port=8080"),
                b"txtvers=1\npath=/api\n",
            )
            .expect("announcing");
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert_eq!(arrived.len(), 1);
        assert!(
            arrived[0]
                .origin_uri
                .ends_with("/Gateway._xmip._tcp.local?port=8080&host=gateway.local."),
            "{}",
            arrived[0].origin_uri
        );
        assert_eq!(arrived[0].bytes, b"txtvers=1\npath=/api\n");
    }

    #[test]
    fn browsing_asks_first_and_takes_every_service_answered() {
        let responder = UdpSocket::bind("127.0.0.1:0").expect("responder");
        responder
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let far_end = node()
            .browsing("_ipp._tcp")
            .asking(&responder.local_addr().expect("address").to_string());
        let (socket, _) = far_end.bind_udp().expect("binding");
        let answering = std::thread::spawn(move || {
            let mut buffer = [0u8; MAX_MESSAGE];
            let (read, peer) = responder.recv_from(&mut buffer).expect("the query");
            let query = message::decode(&buffer[..read]).expect("decode");
            assert!(!query.is_response());
            assert_eq!(query.questions[0].name, "_ipp._tcp.local.");
            assert_eq!(query.questions[0].kind, message::TYPE_PTR);
            let mut records = Vec::new();
            for (instance, port) in [("Printer", 631), ("Copier", 632)] {
                let service = Service {
                    instance: instance.into(),
                    kind: "_ipp._tcp".into(),
                    port,
                    txt: vec![format!("name={instance}")],
                    host: format!("{}.local.", instance.to_lowercase()),
                    addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
                };
                records.extend(service.records(TTL));
            }
            let response = message::encode(&Message::response(0, records)).expect("encode");
            responder.send_to(&response, peer).expect("answering");
        });
        far_end.query(&socket).expect("asking");
        let arrived = far_end.receive_datagram(&socket).expect("answers");
        answering.join().expect("thread");
        assert_eq!(arrived.len(), 2);
        assert!(
            arrived[0]
                .origin_uri
                .ends_with("/Printer._ipp._tcp.local?port=631&host=printer.local.")
        );
        assert_eq!(arrived[0].bytes, b"name=Printer\n");
        assert!(
            arrived[1]
                .origin_uri
                .contains("/Copier._ipp._tcp.local?port=632")
        );
    }

    #[test]
    fn what_is_not_dns_is_refused_and_a_query_is_not_a_service() {
        let far_end = node().timing_out_after(Duration::from_millis(300));
        let (socket, address) = far_end.bind_udp().expect("binding");
        let other = UdpSocket::bind("127.0.0.1:0").expect("sender");
        other.send_to(b"short", &address).expect("junk");
        assert!(
            !far_end
                .receive_datagram(&socket)
                .expect_err("junk")
                .retryable
        );
        let query = message::encode(&Message::query("_ipp._tcp.local.", message::TYPE_PTR));
        other
            .send_to(&query.expect("encode"), &address)
            .expect("query");
        let timed_out = far_end.receive_datagram(&socket).expect_err("skipped");
        assert!(timed_out.retryable);
        assert!(node().send(&address, b"").is_err(), "no service named");
        assert!(
            node()
                .send(&format!("mdns://{address}/x.local"), b"")
                .is_err()
        );
        assert!(
            node()
                .send(&format!("mdns://{address}/A._x._tcp.local"), b"")
                .is_err()
        );
        assert!(node().send("http://x/A._x._tcp.local?port=1", b"").is_err());
        let (group, port) = multicast_group(GROUP).expect("multicast");
        assert_eq!(group, Ipv4Addr::new(224, 0, 0, 251));
        assert_eq!(port, "0.0.0.0:5353");
        assert!(multicast_group("127.0.0.1:5353").is_none());
        assert!(node().claims().is_none());
        assert_eq!(node().name(), "mdns");
    }
}
