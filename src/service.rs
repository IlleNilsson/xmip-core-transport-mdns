//! RFC 6763: one service instance as the four records DNS-SD spreads it
//! over, and back. `<instance>.<kind>.local.` is the SRV and TXT owner;
//! `<kind>.local.` has a PTR to it; the SRV names a host that A and AAAA
//! records place.

use std::net::IpAddr;

use crate::message::{
    BIT_UNICAST, CLASS_IN, Record, RecordData, TYPE_A, TYPE_AAAA, TYPE_PTR, TYPE_SRV, TYPE_TXT,
};

/// The domain every mDNS name ends in.
pub const DOMAIN: &str = "local.";

/// One service instance: `Printer` of kind `_ipp._tcp` on port 631 at
/// `printer.local.`, with its TXT strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    pub instance: String,
    pub kind: String,
    pub port: u16,
    pub txt: Vec<String>,
    pub host: String,
    pub addresses: Vec<IpAddr>,
}

impl Service {
    /// `<instance>.<kind>.local.`.
    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.instance, self.kind_name())
    }

    /// `<kind>.local.`.
    #[must_use]
    pub fn kind_name(&self) -> String {
        format!("{}.{DOMAIN}", self.kind.trim_end_matches('.'))
    }

    /// The instance and kind in `<instance>.<kind>.local.`, where the name
    /// is one: the instance is the first label, the kind what follows it up
    /// to the domain. An instance with a dot in it is not told apart here.
    #[must_use]
    pub fn split_name(name: &str) -> Option<(String, String)> {
        let name = name.strip_suffix(DOMAIN)?.strip_suffix('.')?;
        let (instance, kind) = name.split_once('.')?;
        (!instance.is_empty() && kind.starts_with('_'))
            .then(|| (instance.to_string(), kind.to_string()))
    }

    /// The record set announcing this service, each record living `ttl`
    /// seconds and replacing what a cache held.
    #[must_use]
    pub fn records(&self, ttl: u32) -> Vec<Record> {
        let full = self.full_name();
        let record = |name: &str, kind: u16, data: RecordData| Record {
            name: name.to_string(),
            kind,
            class: CLASS_IN | BIT_UNICAST,
            ttl,
            data,
        };
        let mut records = vec![
            Record {
                class: CLASS_IN,
                ..record(&self.kind_name(), TYPE_PTR, RecordData::Ptr(full.clone()))
            },
            record(
                &full,
                TYPE_SRV,
                RecordData::Srv {
                    priority: 0,
                    weight: 0,
                    port: self.port,
                    target: self.host.clone(),
                },
            ),
            record(&full, TYPE_TXT, RecordData::Txt(self.txt.clone())),
        ];
        for address in &self.addresses {
            records.push(match address {
                IpAddr::V4(v4) => record(&self.host, TYPE_A, RecordData::A(*v4)),
                IpAddr::V6(v6) => record(&self.host, TYPE_AAAA, RecordData::Aaaa(*v6)),
            });
        }
        records
    }

    /// Every service `records` describe: one per SRV record whose owner is
    /// an instance name, with the TXT strings and addresses that go with it.
    #[must_use]
    pub fn from_records<'a>(records: impl Iterator<Item = &'a Record> + Clone) -> Vec<Self> {
        let mut services = Vec::new();
        let all = records.clone();
        for record in records {
            let RecordData::Srv { port, target, .. } = &record.data else {
                continue;
            };
            let Some((instance, kind)) = Self::split_name(&record.name) else {
                continue;
            };
            let txt = all
                .clone()
                .filter(|r| r.kind == TYPE_TXT && r.name.eq_ignore_ascii_case(&record.name))
                .flat_map(|r| match &r.data {
                    RecordData::Txt(strings) => strings.clone(),
                    _ => Vec::new(),
                })
                .collect();
            let addresses = all
                .clone()
                .filter(|r| r.name.eq_ignore_ascii_case(target))
                .filter_map(|r| match &r.data {
                    RecordData::A(v4) => Some(IpAddr::V4(*v4)),
                    RecordData::Aaaa(v6) => Some(IpAddr::V6(*v6)),
                    _ => None,
                })
                .collect();
            services.push(Self {
                instance,
                kind,
                port: *port,
                txt,
                host: target.clone(),
                addresses,
            });
        }
        services
    }

    /// The TXT strings as the Stream: one `key=value` line each.
    #[must_use]
    pub fn txt_lines(&self) -> Vec<u8> {
        let mut out = String::new();
        for string in &self.txt {
            out.push_str(string);
            out.push('\n');
        }
        out.into_bytes()
    }

    /// The TXT strings a Stream of lines names; blank lines skipped.
    #[must_use]
    pub fn parse_txt(bytes: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(bytes)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToString::to_string)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn printer() -> Service {
        Service {
            instance: "Printer".into(),
            kind: "_ipp._tcp".into(),
            port: 631,
            txt: Service::parse_txt(b"txtvers=1\n\n rp=ipp/print \n"),
            host: "printer.local.".into(),
            addresses: vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        }
    }

    #[test]
    fn a_service_spreads_over_its_records_and_gathers_back() {
        let service = printer();
        assert_eq!(service.full_name(), "Printer._ipp._tcp.local.");
        let records = service.records(120);
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].kind, TYPE_PTR);
        assert_eq!(records[0].class, CLASS_IN, "a shared record does not flush");
        assert_eq!(records[1].class, CLASS_IN | BIT_UNICAST);
        assert_eq!(records[3].name, "printer.local.");
        let back = Service::from_records(records.iter());
        assert_eq!(back, vec![service.clone()]);
        assert_eq!(service.txt_lines(), b"txtvers=1\nrp=ipp/print\n");
        let none = Service::from_records(records[..1].iter());
        assert!(none.is_empty(), "a PTR alone is not a service");
        assert_eq!(
            Service::split_name("Printer._ipp._tcp.local."),
            Some(("Printer".into(), "_ipp._tcp".into()))
        );
        assert!(Service::split_name("printer.local.").is_none(), "a host");
        assert!(Service::split_name("Printer._ipp._tcp.example.").is_none());
        assert!(Service::split_name("._ipp._tcp.local.").is_none());
    }
}
