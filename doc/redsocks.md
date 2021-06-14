### Configuration

```jsonc
{
  "setting": {
    "daemon": false,
    "log_level": "info"
  },
  "in": [
    {
      "tag": "tproxy",
      "protocol": "tproxy",
      "address": "[::]:1110",
      "tcp_nodelay": true,
      "tcp_keepalive_interval": 30,
      "tcp_timeout": 300,
      "udp_timeout": 60
    }
  ],
  "out": [
    {
      "tag": "origin",
      "protocol": "origin",
      "tcp_nodelay": true,
      "tcp_keepalive_interval": 30,
      "tcp_timeout": 300,
      "udp_timeout": 60
    },
    {
      "tag": "socks5",
      "protocol": "socks5",
      "address": "1.2.3.4:1080",
      "tcp_timeout": 300,
      "udp_timeout": 60
    }
  ],
  "route": [
    {
      "tag": ["tproxy"],
      "jump": "socks5"
    }
  ]
}
```

### Shell script

```bash
iptables -t mangle -A OUTPUT -d 0.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,192.0.0.0/24,192.0.2.0/24,192.88.99.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8,224.0.0.0/3 -j ACCEPT
iptables -t mangle -A OUTPUT -m owner --uid-owner nobody -j MARK --set-mark 0x1100
iptables -t mangle -A PREROUTING -p tcp -m mark --mark 0x1100 -j TPROXY --on-port 1110 --tproxy-mark 0x1100
iptables -t mangle -A PREROUTING -p udp -m mark --mark 0x1100 -j TPROXY --on-port 1110 --tproxy-mark 0x1100
ip route add local default dev lo table 1100
ip rule add fwmark 0x1100 lookup 1100
```

### Tip

- only user `nobody` proxied
