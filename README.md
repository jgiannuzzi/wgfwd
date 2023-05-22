# wgfwd

## Description

`wgfwd` is a user-space Wireguard implementation that can forward TCP and UDP ports from one node to another.
You can think of it as SSH port-forwarding, but with lower latency as Wireguard uses UDP under the hood.

## Install

Browse the [releases](https://github.com/jgiannuzzi/wgfwd/releases) and download a binary for your platform.

Alternatively, you can build it yourself after having installed the [Go](https://go.dev) SDK by running the following command:
```sh
go install github.com/jgiannuzzi/wgfwd@latest
```

## Usage

### Basic

`wgfwd` works like regular Wireguard.

Here is an example configuration of `wgfwd` acting as a client that forwards TCP and UDP ports 4000 through the tunnel:

```sh
wgfwd \
-wg-private-key mMw8xmuUyfiEwn1Q9v5EEAPqtLtU5aO5gc00+tegiWA= \
-wg-public-key jwYGod+ALPjuKAvEQ7Os1RLgGfcMnwXL97G5mbDW5XU= \
-wg-local-ip 192.168.4.2 \
-wg-remote-ip 192.168.4.1 \
-wg-endpoint 10.8.43.5:58120 \
-wg-keepalive 25 \
-fwd tcp:4000:192.168.4.1:4000,udp:4000:192.168.4.1:4000
```

It connects to a regular Wireguard server running on `10.8.43.5:58120` with this configuration file:
```ini
[Interface]
PrivateKey = WJiRwPPp1NnNl1PbEAtH0yeG160xxPXXe+8OFxk6H1o=
Address = 192.168.4.1/32
ListenPort = 58120
MTU = 1420

[Peer]
PublicKey = +t6LAA9uaC1RXp2GzXQKCuwkys6Q2188EnAgU26P6xc=
AllowedIPs = 192.168.4.2/32
```

The server could also use `wgfwd` as follows:
```sh
wgfwd \
-wg-private-key WJiRwPPp1NnNl1PbEAtH0yeG160xxPXXe+8OFxk6H1o= \
-wg-public-key +t6LAA9uaC1RXp2GzXQKCuwkys6Q2188EnAgU26P6xc= \
-wg-local-ip 192.168.4.1 \
-wg-remote-ip 192.168.4.2 \
-wg-listen-port 58120 \
-fwd tcp:192.168.4.1:4000:localhost:4000,udp:192.168.4.1:4000:localhost:4000
```

Note that in this case, we need to forward the 2 ports back onto the real host, as opposed to when regular Wireguard is used.

### Advanced

`-wg-config` can be used to point to a config file that uses the [Wireguard configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol) format.

Here is what the file would look like for the client case above:
```
private_key=98cc3cc66b94c9f884c27d50f6fe441003eab4bb54e5a3b981cd34fad7a08960
public_key=8f0606a1df802cf8ee280bc443b3acd512e019f70c9f05cbf7b1b999b0d6e575
allowed_ip=192.168.4.1/32
endpoint=10.8.43.5:58120
persistent_keepalive_interval=25
```

The corresponding command line is:
```
wgfwd \
-wg-local-ip 192.168.4.2 \
-wg-config client.cfg \
-fwd tcp:4000:192.168.4.1:4000,udp:4000:192.168.4.1:4000
```
