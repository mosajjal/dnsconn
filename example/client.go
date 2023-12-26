package main

import (
	"fmt"
	"net"
	"time"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
)

func main() {
	// generate a new private key
	privateKey, _ := cryptography.GenerateKey()

	serverPubcliKey, _ := cryptography.PublicKeyFromString("iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40")

	clientPc := dnsconn.DialDNST(privateKey, serverPubcliKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300})
	defer clientPc.Close()

	for {
		// list active clients every 3 seconds
		time.Sleep(3 * time.Second)
		fmt.Printf("Active clients: %+#v\n", clientPc)
	}

}
