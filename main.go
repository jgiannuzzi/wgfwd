package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var version = "dev"

func main() {
	forwards := flag.String("fwd", "", "TCP/UDP forwarding list (<tcp|udp>:[local-ip]:local-port:remote-ip:remote-port,...)")
	wgConfig := flag.String("wg-config", "", "Wireguard config file")
	wgListenPort := flag.Int("wg-listen-port", 0, "Wireguard listen port")
	wgLocalIP := flag.String("wg-local-ip", "", "Wireguard local IP")
	wgRemoteIP := flag.String("wg-remote-ip", "", "Wireguard remote IP")
	wgPrivateKey := flag.String("wg-private-key", "", "Wireguard private key")
	wgPublicKey := flag.String("wg-public-key", "", "Wireguard public key")
	wgEndpoint := flag.String("wg-endpoint", "", "Wireguard endpoint")
	wgKeepalive := flag.Int("wg-keepalive", 0, "Wireguard keepalive")
	logLevelString := flag.String("log-level", "info", "Log level")
	showVersion := flag.Bool("version", false, "Show version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("wgfwd %s\n", version)
		return
	}

	logLevel, err := logrus.ParseLevel(*logLevelString)
	if err != nil {
		log.Fatal(err)
	}
	logrus.SetLevel(logLevel)

	if *wgConfig == "" {
		if *wgPrivateKey == "" {
			logrus.Fatal("Wireguard private key is required")
		}

		if *wgPublicKey == "" {
			logrus.Fatal("Wireguard public key is required")
		}

		if *wgRemoteIP == "" {
			logrus.Fatal("Wireguard remote IP is required")
		}
	}

	if *wgLocalIP == "" {
		logrus.Fatal("Wireguard local IP is required")
	}

	if !strings.Contains(*wgRemoteIP, "/") {
		*wgRemoteIP = *wgRemoteIP + "/32"
	}

	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr(*wgLocalIP)},
		[]netip.Addr{},
		1420,
	)
	if err != nil {
		logrus.Fatalf("Error creating tunnel interface: %s", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: logrus.Debugf,
		Errorf:   logrus.Errorf,
	})

	var config string
	if *wgConfig != "" {
		content, err := os.ReadFile(*wgConfig)
		if err != nil {
			logrus.Fatalf("Error reading Wireguard config file: %s", err)
		}
		config = string(content)
	} else {
		configBuilder := strings.Builder{}
		fmt.Fprintf(&configBuilder, "private_key=%s\n", base64ToHex(*wgPrivateKey))
		if *wgListenPort != 0 {
			fmt.Fprintf(&configBuilder, "listen_port=%d\n", *wgListenPort)
		}
		fmt.Fprintf(&configBuilder, "public_key=%s\n", base64ToHex(*wgPublicKey))
		fmt.Fprintf(&configBuilder, "allowed_ip=%s\n", *wgRemoteIP)
		if *wgEndpoint != "" {
			fmt.Fprintf(&configBuilder, "endpoint=%s\n", *wgEndpoint)
		}
		if *wgKeepalive != 0 {
			fmt.Fprintf(&configBuilder, "persistent_keepalive_interval=%d\n", *wgKeepalive)
		}
		config = configBuilder.String()
	}

	if err := dev.IpcSet(config); err != nil {
		logrus.Fatalf("Error setting device configuration: %s", err)
	}

	if err := dev.Up(); err != nil {
		logrus.Fatalf("Error bringing up device: %s", err)
	}
	logrus.Infof("Wireguard device up")
	defer dev.Down()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var localNetOp = &localNetOp{}
	var tunnelNetOp = &tunnelNetOp{tnet}

	if len(*forwards) != 0 {
		for _, fwd := range strings.Split(*forwards, ",") {
			components := strings.Split(fwd, ":")
			if len(components) == 4 {
				components = append([]string{components[0], "127.0.0.1"}, components[1:]...)
			}
			if len(components) != 5 {
				logrus.Fatalf("Invalid forward: %s", fwd)
			}
			proto := components[0]
			var lNet netOp
			var rNet netOp
			if components[1] == *wgLocalIP {
				lNet = tunnelNetOp
				rNet = localNetOp
			} else {
				lNet = localNetOp
				rNet = tunnelNetOp
			}
			lAddr := strings.Join(components[1:3], ":")
			rAddr := strings.Join(components[3:], ":")
			if err := forward(ctx, &wg, proto, lNet, lAddr, rNet, rAddr); err != nil {
				log.Fatalf("Error forwarding %s: %s", fwd, err)
			}
		}
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

// decode base64 string and encode it to hex string
func base64ToHex(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		logrus.Fatalf("Error decoding base64: %s", err)
	}
	return hex.EncodeToString(b)
}

type netOp interface {
	Dial(ctx context.Context, network string, address string) (net.Conn, error)
	Listen(ctx context.Context, network string, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error)
}

type localNetOp struct{}

func (n *localNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (n *localNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	var l net.ListenConfig
	return l.Listen(ctx, network, address)
}

func (n *localNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	var l net.ListenConfig
	return l.ListenPacket(ctx, network, address)
}

type tunnelNetOp struct {
	tun *netstack.Net
}

func (n *tunnelNetOp) Dial(ctx context.Context, network string, address string) (net.Conn, error) {
	return n.tun.DialContext(ctx, network, address)
}

func (n *tunnelNetOp) Listen(ctx context.Context, network string, address string) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return n.tun.ListenTCP(addr)
}

func (n *tunnelNetOp) ListenPacket(ctx context.Context, network string, address string) (net.PacketConn, error) {
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	return n.tun.ListenUDP(addr)
}

func forward(ctx context.Context, wg *sync.WaitGroup, proto string, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	switch proto {
	case "tcp":
		return forwardTCP(ctx, wg, lNet, lAddr, rNet, rAddr)
	case "udp":
		return forwardUDP(ctx, wg, lNet, lAddr, rNet, rAddr)
	default:
		return fmt.Errorf("unknown protocol: %s", proto)
	}
}

func forwardTCP(ctx context.Context, wg *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	wg.Add(1)

	listener, err := lNet.Listen(ctx, "tcp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		logrus.Infof("Stopping TCP forwarder for %s -> %s", lAddr, rAddr)
		listener.Close()
	}()

	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				logrus.Debugf("Error accepting TCP connection: %s", err)
				return
			}
			logrus.Debugf("Accepted TCP connection from %s for %s", conn.RemoteAddr(), lAddr)

			remote, err := rNet.Dial(ctx, "tcp", rAddr)
			if err != nil {
				logrus.Errorf("Error connecting to remote TCP: %s", err)
				conn.Close()
				continue
			}
			logrus.Debugf("TCP connection forwarded from %s to %s", conn.RemoteAddr(), rAddr)

			var iwg sync.WaitGroup
			go func() {
				defer iwg.Done()
				defer remote.Close()
				defer conn.Close()
				_, err := io.Copy(remote, conn)
				if err != nil && err != io.EOF {
					logrus.Debugf("Error copying from %s: %s", conn.RemoteAddr(), err)
				}
			}()
			go func() {
				defer iwg.Done()
				defer remote.Close()
				defer conn.Close()
				_, err := io.Copy(conn, remote)
				if err != nil {
					logrus.Debugf("Error copying to %s: %s", conn.RemoteAddr(), err)
				}
			}()
			iwg.Add(2)
			go func() {
				iwg.Wait()
				logrus.Debugf("Connection from %s closed", conn.RemoteAddr())
			}()
		}
	}()

	logrus.Infof("TCP forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}

func forwardUDP(ctx context.Context, wg *sync.WaitGroup, lNet netOp, lAddr string, rNet netOp, rAddr string) error {
	wg.Add(1)

	remoteConns := make(map[string]net.Conn)

	localConn, err := lNet.ListenPacket(ctx, "udp", lAddr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		logrus.Infof("Stopping UDP forwarder for %s -> %s", lAddr, rAddr)
		for _, c := range remoteConns {
			c.Close()
		}
		localConn.Close()
	}()

	buffer := make([]byte, 1392)
	go func() {
		defer wg.Done()

		for {
			n, addr, err := localConn.ReadFrom(buffer)
			if err != nil {
				logrus.Debugf("Error reading from UDP socket: %#v", err)
				return
			}
			logrus.Debugf("Received %d bytes from %s for %s", n, addr, lAddr)

			remote, ok := remoteConns[addr.String()]
			if !ok {
				remote, err = rNet.Dial(ctx, "udp", rAddr)
				if err != nil {
					logrus.Errorf("Error connecting to remote UDP: %s", err)
					continue
				}
				remoteConns[addr.String()] = remote

				go func() {
					defer delete(remoteConns, addr.String())

					buffer := make([]byte, 1392)
					for {
						remote.SetReadDeadline(time.Now().Add(3 * time.Second))
						n, err = remote.Read(buffer)
						if err != nil {
							logrus.Debugf("Error reading from UDP socket: %s", err)
							return
						}
						logrus.Debugf("Received %d bytes from %s for %s", n, rAddr, remote.LocalAddr())
						_, err = localConn.WriteTo(buffer[:n], addr)
						if err != nil {
							logrus.Debugf("Error writing to local: %s", err)
							return
						}
						logrus.Debugf("Forwarded %d bytes from %s to %s", n, rAddr, addr)
					}
				}()
			}

			n, err = remote.Write(buffer[:n])
			if err != nil {
				logrus.Errorf("Error writing to remote UDP from %s: %s", addr, err)
				continue
			}
			logrus.Debugf("Forwarded %d bytes from %s to %s", n, addr, rAddr)
		}
	}()

	logrus.Infof("UDP forwarder started for %s -> %s", lAddr, rAddr)

	return nil
}
