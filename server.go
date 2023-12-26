package dnsconn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mosajjal/dnsconn/cryptography"
	"github.com/mosajjal/dnsconn/transport"
)

type DNSTAddr struct {
	pubKey cryptography.PublicKey
}

func (a *DNSTAddr) Network() string {
	return "dnsconn"
}

func (a *DNSTAddr) String() string {
	return string(a.pubKey.String())
}

type clientStatus struct {
	LastAckFromAgentServerTime uint32
	LastAckFromAgentPacketTime uint32
	inLock                     *sync.Mutex
	inPacketBuffer             map[transport.PartID][]transport.MessagePacketWithSignature
	inBuffer                   []byte
	outLock                    *sync.Mutex
	outPacketBuffer            map[transport.PartID][]transport.FQDN
}

func (c *clientStatus) OutPop(partID transport.PartID) transport.FQDN {
	// pops the first element of outPacketBuffer[partID]
	c.outLock.Lock()
	defer c.outLock.Unlock()
	if len(c.outPacketBuffer[partID]) == 0 {
		return ""
	}
	fqdn := c.outPacketBuffer[partID][0]
	c.outPacketBuffer[partID] = c.outPacketBuffer[partID][1:]
	return fqdn
}
func (c *clientStatus) OutPush(partID transport.PartID, fqdns ...transport.FQDN) {
	c.outLock.Lock()
	defer c.outLock.Unlock()
	c.outPacketBuffer[partID] = append(c.outPacketBuffer[partID], fqdns...)
}

// implements net.PacketConn
type Server struct {
	Listener           net.PacketConn // DNS Tunnel works on top of a dns server (udp, tcp, tls, unix socket etc). The design is decoupled from the nature of the socket
	DNSSuffix          string         // top level suffix expected
	privateKey         *cryptography.PrivateKey
	acceptedClientKeys []*cryptography.PublicKey                   // if not empty, only comms from these keys will be accepted
	clients            map[cryptography.PublicKeyStr]*clientStatus // list of current clients. key can't be the actual public key because golang doesn't support struct custom equal functions. need to use the string
	// dedupPrevMsgHash is only for consecutive message duplicates
	dedupPrevMsgHash uint64 // since dns servers send multiple queries at the same time, simple dedup helps
	ctx              context.Context
}

// ListenDNST creates a new DNS Tunnel server. It will return a net.PacketConn that can be used to send and receive any arbitrary payload
// parameters:
//   - privateKey: the private key of the agent. can be empty. in which case, a new private key will be generated on the fly
//   - listener: the underlying packet listener used for dns tunneling. cannot be nil
//   - dnsSuffix: the DNS suffix of the server. cannot be empty and MUST have a trailing and leading dot
//   - acceptedClientKeys: if not empty, only comms from these keys will be accepted
func ListenDNST(privateKey *cryptography.PrivateKey, listener net.PacketConn, dnsSuffix string, acceptedClientKeys ...*cryptography.PublicKey) (*Server, error) {
	if privateKey == nil {
		// generate a new private key
		privateKey, _ = cryptography.GenerateKey()
	}
	if listener == nil {
		return nil, errors.New("listener cannot be nil")
	}
	if dnsSuffix == "" {
		return nil, errors.New("dns suffix cannot be empty")
	}

	server := &Server{
		Listener:           listener,
		DNSSuffix:          dnsSuffix,
		privateKey:         privateKey,
		acceptedClientKeys: acceptedClientKeys,
		clients:            make(map[cryptography.PublicKeyStr]*clientStatus),
		dedupPrevMsgHash:   0,
		ctx:                context.Background(),
	}

	dns.HandleFunc(".", server.handleDNS)

	dnsServer := dns.Server{
		PacketConn: listener,
	}
	go dnsServer.ActivateAndServe()
	return server, nil
}

// handleDNS is the main point of entry for incoming DNS packets
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	switch r.Opcode {
	case dns.OpcodeQuery:
		payloads, skip, err := transport.DecryptIncomingPacket(m, s.DNSSuffix, s.privateKey, nil)
		if skip || err != nil {
			slog.Warn("failed to decrypt incoming packet", err)
			return
		}
		for _, payload := range payloads {
			// determine the direction of the traffic
			if payload.Msg.Metadata.IsServer2Client() {
				s.handleServerToClient(w, r, payload)

			}
			if payload.Msg.Metadata.IsClient2Server() {
				s.handleClientToServer(w, r, payload)
			}
		}
	}
	if err := w.WriteMsg(m); err != nil {
		slog.Warn("failed to write response", err)
	}
}

func (s *Server) handleServerToClient(w dns.ResponseWriter, r *dns.Msg, emptyPayload transport.MessagePacketWithSignature) {
	// TODO: implement
	// the payload should be empty, respond with a CNAME containing the intended payload buffer. if we have nothing to send, respond with a healthcheck
	var fqdn transport.FQDN
	// check to see if this is the first time we're seeing this client
	if client, ok := s.clients[emptyPayload.Signature.String()]; !ok {
		s.clients[emptyPayload.Signature.String()] = &clientStatus{
			LastAckFromAgentServerTime: uint32(time.Now().Unix()),
			LastAckFromAgentPacketTime: emptyPayload.Msg.TimeStamp,
			inLock:                     &sync.Mutex{},
			inPacketBuffer:             make(map[transport.PartID][]transport.MessagePacketWithSignature),
			inBuffer:                   make([]byte, 0),
			outLock:                    &sync.Mutex{},
			outPacketBuffer:            make(map[transport.PartID][]transport.FQDN),
		}
		// if this is a new client, we don't have anything to send to it yet. so we'll respond with an empty CNAME
		msg := transport.MessagePacket{
			TimeStamp: uint32(time.Now().Unix()),
			Metadata:  transport.PacketMetaData(0),
		}
		msg.Metadata = msg.Metadata.SetIsLastPart(true)
		msg.Metadata = msg.Metadata.SetIsClosing(true)

		cnames, _, err := transport.PreparePartitionedPayload(msg, []byte("pong!"), s.DNSSuffix, s.privateKey, emptyPayload.Signature)
		if err != nil {
			slog.Error("failed to prepare payload", err)
		}
		fqdn = cnames[0]
	} else {
		fqdn = client.OutPop(emptyPayload.Msg.PartID)
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", r.Question[0].Name, fqdn))
	if err != nil {
		slog.Error("failed to create CNAME", err)
	}
	r.Answer = append(r.Answer, cname)
	if err := w.WriteMsg(r); err != nil {
		slog.Warn("failed to write response", err)
	}
}

func (s *Server) handleClientToServer(w dns.ResponseWriter, r *dns.Msg, payload transport.MessagePacketWithSignature) {
	// TODO: implement
	// read the payload, decrypt and verify, and add it to the buffer for the client's public key

	// check to see if this is the first time we're seeing this client
	if client, ok := s.clients[payload.Signature.String()]; !ok {
		s.clients[payload.Signature.String()] = &clientStatus{
			LastAckFromAgentServerTime: uint32(time.Now().Unix()),
			LastAckFromAgentPacketTime: payload.Msg.TimeStamp,
			inLock:                     &sync.Mutex{},
			inPacketBuffer:             make(map[transport.PartID][]transport.MessagePacketWithSignature),
			inBuffer:                   make([]byte, 0),
			outLock:                    &sync.Mutex{},
			outPacketBuffer:            make(map[transport.PartID][]transport.FQDN),
		}
	} else {
		client.inPacketBuffer[payload.Msg.PartID] = append(client.inPacketBuffer[payload.Msg.PartID], payload)
		if payload.Msg.Metadata.IsLastPart() {
			client.inLock.Lock()
			// order and clean up all the payloads
			packets := transport.CheckMessageIntegrity(client.inPacketBuffer[payload.Msg.PartID])
			if packets == nil {
				// the payload does not have the last packet, we should return an empty payload and an error
				slog.Warn("failed to check message integrity")
			}
			for _, packet := range packets {
				packetPayload := packet.Msg.Payload[:]
				client.inBuffer = append(client.inBuffer, packetPayload...)
			}
			delete(client.inPacketBuffer, payload.Msg.PartID)
			client.inLock.Unlock()
		}
	}

	msg := transport.MessagePacket{
		TimeStamp: uint32(time.Now().Unix()),
	}

	cnames, _, err := transport.PreparePartitionedPayload(msg, []byte("pong!"), s.DNSSuffix, s.privateKey, payload.Signature)
	if err != nil {
		slog.Error("failed to prepare payload", err)
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", r.Question[0].Name, cnames[0]))
	if err != nil {
		slog.Error("failed to create CNAME", err)
	}
	r.Answer = append(r.Answer, cname)
	if err := w.WriteMsg(r); err != nil {
		slog.Warn("failed to write response", err)
	}

}

func (s *Server) Close() error {
	return nil
}

func (s *Server) LocalAddr() net.Addr {
	return &DNSTAddr{
		pubKey: s.privateKey.GetPublicKey(),
	}
}

func (s *Server) ListActiveClientPubKeys() []cryptography.PublicKeyStr {
	var keys []cryptography.PublicKeyStr
	for k := range s.clients {
		keys = append(keys, k)
	}
	return keys
}

// ReadFrom Won't be implemented for now
func (s *Server) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}

func (s *Server) ReadFromAddr(b []byte, addr net.Addr) (n int, err error) {
	// try to assert type of addr to Addr
	var dnsAddr *DNSTAddr
	if a, ok := addr.(*DNSTAddr); !ok {
		return 0, errors.New("can't talk to any other protocol other than dnsconn")
	} else {
		dnsAddr = a
	}
	if client, ok := s.clients[dnsAddr.pubKey.String()]; !ok {
		s.clients[dnsAddr.pubKey.String()] = &clientStatus{
			LastAckFromAgentServerTime: uint32(time.Now().Unix()),
			LastAckFromAgentPacketTime: uint32(time.Now().Unix()),
			inLock:                     &sync.Mutex{},
			inPacketBuffer:             make(map[transport.PartID][]transport.MessagePacketWithSignature),
			inBuffer:                   make([]byte, 0),
			outLock:                    &sync.Mutex{},
			outPacketBuffer:            make(map[transport.PartID][]transport.FQDN),
		}
	} else {
		n = copy(b, client.inBuffer)
		client.inLock.Lock()
		client.inBuffer = client.inBuffer[n:]
		client.inLock.Unlock()
	}
	return
}

func (s *Server) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	// try to assert type of addr to Addr
	var dnsAddr *DNSTAddr
	if a, ok := addr.(*DNSTAddr); !ok {
		return 0, errors.New("can't talk to any other protocol other than dnsconn")
	} else {
		dnsAddr = a
	}

	if client, ok := s.clients[dnsAddr.pubKey.String()]; !ok {
		s.clients[dnsAddr.pubKey.String()] = &clientStatus{
			LastAckFromAgentServerTime: uint32(time.Now().Unix()),
			LastAckFromAgentPacketTime: uint32(time.Now().Unix()),
			inLock:                     &sync.Mutex{},
			inPacketBuffer:             make(map[transport.PartID][]transport.MessagePacketWithSignature),
			inBuffer:                   make([]byte, 0),
			outLock:                    &sync.Mutex{},
			outPacketBuffer:            make(map[transport.PartID][]transport.FQDN),
		}
	} else {
		msg := transport.MessagePacket{
			TimeStamp: uint32(time.Now().Unix()),
			Metadata:  transport.PacketMetaData(0),
		}

		fqdns, _, err := transport.PreparePartitionedPayload(msg, b, s.DNSSuffix, s.privateKey, &dnsAddr.pubKey)
		if err != nil {
			slog.Error("failed to prepare payload", err)
		}
		client.outPacketBuffer[msg.PartID] = append(client.outPacketBuffer[msg.PartID], fqdns...)
	}
	return len(b), nil
}

func (s *Server) SetDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
func (s *Server) SetReadDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
func (s *Server) SetWriteDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
