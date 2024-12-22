package transport

import "github.com/mosajjal/dnsconn/cryptography"

// DNSTAddr is a net.Addr implementation for DNS Tunnel
type DNSTAddr struct {
	pubKey cryptography.PublicKey
}

// Network returns the network type
func (a DNSTAddr) Network() string {
	return "dnsconn"
}

func (a DNSTAddr) String() string {
	return string(a.pubKey.String())
}

func (a DNSTAddr) PublicKey() *cryptography.PublicKey {
	return &a.pubKey
}

// NewDNSTAddr creates a new DNSTAddr
func NewDNSTAddr(pubKey cryptography.PublicKey) DNSTAddr {
	return DNSTAddr{
		pubKey: pubKey,
	}
}
