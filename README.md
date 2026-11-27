# xmip-core-transport-mdns

mDNS transport: multicast DNS with DNS-SD over UDP — service announcements and query answers arrive as Streams of their TXT records, a Send Location announces a service. The DNS message codec is the dns technology's; mDNS adds only the size it sends. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16) (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

A Send Location's target is its whole address, `mdns://host:port/<instance>.<kind>.local?port=…`, which a send reads the service it announces from (`Configured::own_target`); until 2026-11-25 it was the address without its scheme, and every send of a node was refused.

## Acknowledgement

An announcement is multicast to the link and answered by nobody, so acceptance
is at-most-once there: its responder is never told how the receive cycle ended,
and a crash before the Stream is durable loses it. A Location built browsing a
kind asks before every receive, and taking an answer consumes nothing at the
responder (the next receive asks again and is answered again), so its
acknowledgement waits for the verdict with nothing to do on either. Each
service arrives whole.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which
`Configured` reads (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `browsing`, `host`, `host_address` and `timeout`,
and `SCHEMES`, `mdns`. Built with its `declaration` feature alone
(`--no-default-features --features declaration`), the crate is those and
nothing more: its code and every crate the code is built on are behind the
default feature, the dns technology whose messages the code reads and writes
included. So the library the surfaces load carries it without the code,
through the gathering crate xmip-core-declaration (open problem 48), and the
language server and the desktop suggest and check an mDNS Location's
settings though no node in their process loaded the technology.
`test/Declaration.Test.ps1` in the estate holds that the declaration builds
nothing the transport capability does not.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
