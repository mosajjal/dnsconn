package main

import (
	"net"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
	"github.com/things-go/go-socks5"
)

func main() {
	// generate a new private key
	privateKey, _ := cryptography.GenerateKey()

	serverPubcliKey, _ := cryptography.PublicKeyFromString("iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40")

	dnstConn := dnsconn.DialDNST(privateKey, serverPubcliKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300})
	defer dnstConn.Close()

	sf := socks5.NewServer()

	sf.Proxy(dnstConn)

	sf.ListenAndServe("tcp", ":1080")

}
