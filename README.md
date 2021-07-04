# stn

This project makes your network full of possibilities.

## Build

```bash
git clone https://github.com/FH0/stn.git
cd stn
cargo update
cargo build --no-default-features --bin stn --release
```

The compiled file is `target/release/stn`.

## Configuration

- [replace Redsocks](doc/redsocks.md)
- [full description](doc/configuration.md)

## Todo

- `sniff` out, get http and https domain from tcp stream
- `redirect` out, like iptables DNAT
- `tun` in

## Script

- [bat script to set http proxy](doc/http_bat.md)
