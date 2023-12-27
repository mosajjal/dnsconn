package main

import (
	"context"
	"net"

	"github.com/armon/go-socks5"
	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
)

func dnsTunnelDialer(network, addr string) (net.Conn, error) {

}

func main() {
	// generate a new private key
	privateKey, _ := cryptography.GenerateKey()

	serverPubKey, _ := cryptography.PublicKeyFromString("iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40")

	dnstConn := dnsconn.DialDNST(privateKey, serverPubKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300})
	defer dnstConn.Close()

	socks5Config := socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dnsconn.DialDNST(privateKey, serverPubKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}), nil
		},
	}

	sf, _ := socks5.New()

	sf.ListenAndServe("tcp", ":1080")

}
