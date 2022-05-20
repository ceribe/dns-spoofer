# dns-spoofer

# Prerequisites

## Enable ip forwarding

```sh
echo "1" > /proc/sys/net/ipv4/ip_forward
```

## Add routing via iptables

```sh
sudo iptables -t mangle -I PREROUTING -p udp --dport 53 -j DROP
sudo iptables -t nat -A POSTROUTING -o wlo1 -j MASQUERADE
```
