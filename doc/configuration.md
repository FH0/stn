### setting

- just setting

### in

- Listening on the actual port
- Support `tcp_nodelay` and `tcp_keepalive_interval`
- Can only be processed once by `route`.

### out

- Can be processed multiple times by `route`.

### route

- For `in`, `saddr` match actual `saddr`; for `out`, `saddr` match previous `tag`. Set `log_level` to debug and check the log.

### full.json

```jsonc
{
  "setting": {
    "daemon": false, // default false, only support linux
    "pid_file": "", // invalid by default
    "log_level": "debug", // [debug, info, warn, error] default error
    "log_file": "", // default stdout
    "log_file_max": 1024, // default 1024(KB)
    "uid": 0, // invalid by default, only support linux
    "gid": 1110 // invalid by default, only support linux
  },
  "in": [
    {
      "tag": "socks5_client",
      "protocol": "socks5",
      "address": "[::]:10801",
      "tcp_nodelay": true,
      "tcp_keepalive_interval": 30, // 0 means don't set
      "tcp_timeout": 300,
      "udp_timeout": 60
    },
    {
      "tag": "http_client",
      "protocol": "http",
      "address": "[::]:10802",
      "tcp_nodelay": true,
      "tcp_keepalive_interval": 30,
      "tcp_timeout": 300
    },
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
      "tag": "socks5_server",
      "protocol": "socks5",
      "address": "1.2.3.4:10801",
      "tcp_timeout": 300,
      "udp_timeout": 60
    },
    {
      "tag": "http_server",
      "protocol": "http",
      "address": "1.2.3.4:10802",
      "tcp_timeout": 300
    }
  ],
  "route": [
    {
      "tag": [],
      "network": ["tcp", "udp"],
      "saddr": [
        "full a.com",
        "substring a.com",
        "domain a.com", // match a.com a.a.com, doesn't match aa.com
        "cidr 8.8.8.8/32",
        "cidr ::1/128",
        "regex (^|\\.)a.com" // For poor performance, use should be reduced.
      ],
      "sport": [],
      "daddr": [],
      "dport": [],
      "jump": ""
    }
  ]
}
```
