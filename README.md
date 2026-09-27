# xmip-core-transport-mdns

mDNS transport: multicast DNS with DNS-SD over UDP — service announcements and query answers arrive as Streams of their TXT records, a Send Location announces a service. The DNS message codec is the dns technology's; mDNS adds only the size it sends. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound on the first receive (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
