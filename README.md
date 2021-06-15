# stn

This project makes your network full of possibilities.

## Build

```bash
git clone https://github.com/FH0/stn.git
cd stn
cargo update
cargo build --bin stn --release
```

The compiled file is `target/release/stn`.

## Configuration

- [replace Redsocks](doc/redsocks.md)
- [full description](doc/configuration.md)

## Todo

- [ ] `sniff` out, get http and https domain from tcp stream
- [ ] `resolve` and `dns` out
- [ ] `origin` in, like dns packet, needn't daddr
- [ ] `redirect` out, like iptables DNAT
- [ ] `drop` out, like iptables DROP
- [ ] `tun` in
