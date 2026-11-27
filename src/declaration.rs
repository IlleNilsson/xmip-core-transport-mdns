//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`. It names no
//! setting of the dns technology's, whose messages it reads and writes in its
//! code alone.

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens: the group, `224.0.0.251:5353`, for what the
/// link announces, or a unicast address for answers to its own query. A
/// Send Location announces to its target.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "browsing",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The service kind, `_ipp._tcp`, asked for before taking answers.",
            applies: Applies::Receive,
        },
        Setting {
            name: "host",
            kind: Kind::Text,
            presence: Presence::Optional,
            meaning: "The host an announced service runs on, placed in `local.`.",
            applies: Applies::Send,
        },
        Setting {
            name: "host_address",
            kind: Kind::Address,
            presence: Presence::Optional,
            meaning: "The IP address announced for the host.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Receive,
            None,
            "How long a message is waited for; unbounded when left out.",
        ),
    ],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["mdns"];
