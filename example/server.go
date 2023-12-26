package main

import (
	"fmt"
	"net"
	"time"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
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

	dnsPc, err := dnsconn.ListenDNST(privateKey, pc, ".example.com.", nil)
	if err != nil {
		panic(err)
	}

	defer dnsPc.Close()
	// make it ping pong
	for {
		// list active clients every 3 seconds
		time.Sleep(3 * time.Second)
		fmt.Printf("Active clients: %+#v\n", dnsPc.ListActiveClientPubKeys())
	}

}
