package main

import (
	"bufio"
	"fmt"
	"net"

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

	// TODO: this can have a client handler function that will be called when a new client connects. each function will be run out of a separate goroutine
	dnstListener, err := dnsconn.ListenDNST(privateKey, pc, ".example.com.", nil)
	if err != nil {
		panic(err)
	}

	defer dnstListener.Close()
	// make it ping pong
	for {
		// Accept new connections
		conn, err := dnstListener.Accept()
		if err != nil {
			fmt.Println(err)
		}
		// Handle new connections in a Goroutine for concurrency
		go handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read from the connection untill a new line is send
	data, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("error2: %s\n", err)
		return
	}

	// Print the data read from the connection to the terminal
	fmt.Print("> ", string(data))

	// Write back the same message to the client
	conn.Write([]byte("Hello TCP Client\n"))

}
