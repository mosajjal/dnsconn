package main

import (
	"net"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
	"github.com/things-go/go-socks5"
)

func main() {

	// hardcoded server key
	// 	public key: iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40
	// private key: 4l8gdqjhxjspyr09marce7wvm5qfujrrxpn4xtf8mnw3x95jx9

	privateKey, _ := cryptography.PrivateKeyFromString("4l8gdqjhxjspyr09marce7wvm5qfujrrxpn4xtf8mnw3x95jx9")

	// start listening on udp5300
	pc, err := net.ListenPacket("udp", ":5300")
	if err != nil {
		panic(err)
	}
	defer pc.Close()

	// TODO: this can have a client handler function that will be called when a new client connects. each function will be run out of a separate goroutine
	dnstListener, err := dnsconn.ListenDNST(privateKey, pc, ".example.com.", nil)
	if err != nil {
		panic(err)
	}

	defer dnstListener.Close()
	sf := socks5.NewServer()
	sf.Serve(dnstListener)
}
