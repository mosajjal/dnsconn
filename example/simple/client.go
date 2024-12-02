package main

import (
	"bufio"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/mosajjal/dnsconn"
	"github.com/mosajjal/dnsconn/cryptography"
)

var log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{}))

func main() {
	// generate a new private key
	privateKey, _ := cryptography.GenerateKey()

	serverPubcliKey, _ := cryptography.PublicKeyFromString("iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40")

	go func() {
		dnstConn, err := dnsconn.DialDNST(
			dnsconn.WithPrivateKey(privateKey),
			dnsconn.WithServerPublicKey(serverPubcliKey),
			dnsconn.WithDNSSuffix(".example.com."),
			dnsconn.WithResolver(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}),
		)
		if err != nil {
			log.Error("error dialing to connection",
				"msg", err)
			os.Exit(1)
		}

		defer dnstConn.Close()

		// Send a message to the server
		_, err = dnstConn.Write([]byte("Hello TCP Server\n"))
		if err != nil {
			log.Error("error writing to connection",
				"msg", err)
			os.Exit(1)

		}

		// Read from the connection untill a new line is send
		data, err := bufio.NewReader(dnstConn).ReadString('\n')
		if err != nil {
			log.Error("error reading from connection",
				"msg", err)
			return

		}

		// Print the data read from the connection to the terminal
		log.Info("message received",
			"msg", string(data))
	}()
	// dnstConn := dnsconn.DialDNST(privateKey, serverPubcliKey, ".example.com.", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300})
	dnstConn, err := dnsconn.DialDNST(
		dnsconn.WithPrivateKey(privateKey),
		dnsconn.WithServerPublicKey(serverPubcliKey),
		dnsconn.WithDNSSuffix(".example.com."),
		dnsconn.WithResolver(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5300}),
	)

	defer dnstConn.Close()

	// Send a message to the server
	log.Debug("sending message to server",
		"msg", "Hello TCP Server")
	_, err = dnstConn.Write([]byte("Hello TCP Server\n"))
	if err != nil {
		log.Error("error writing to connection",
			"msg", err)
		os.Exit(1)
	}

	// Read from the connection untill a new line is send
	data, err := bufio.NewReader(dnstConn).ReadString('\n')
	if err != nil {
		log.Error("error reading from connection",
			"msg", err)
		return
	}

	// Print the data read from the connection to the terminal
	log.Info("message received",
		"msg", string(data))

	time.Sleep(10 * time.Second)
}
