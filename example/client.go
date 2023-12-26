package main

import (
	"bufio"
	"fmt"
	"net"
	"os"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
)

func main() {
	// generate a new private key
	privateKey, _ := cryptography.GenerateKey()

	serverPubcliKey, _ := cryptography.PublicKeyFromString("iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40")

	dnstConn := dnsconn.DialDNST(privateKey, serverPubcliKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300})
	defer dnstConn.Close()

	// Send a message to the server
	_, err := dnstConn.Write([]byte("Hello TCP Server\n"))
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	// Read from the connection untill a new line is send
	data, err := bufio.NewReader(dnstConn).ReadString('\n')
	if err != nil {
		fmt.Printf("Error2: %s\n", err)
		return
	}

	// Print the data read from the connection to the terminal
	fmt.Print("> ", string(data))

}
