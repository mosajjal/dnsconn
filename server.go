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

const (
	defaultCleanupInterval = time.Minute
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

// implements net.Conn
type clientStatus struct {
	ConnID                     transport.ConnID
	LastAckFromAgentServerTime uint32
	LastAckFromAgentPacketTime uint32
	inPacketBuffer             []transport.MessagePacketWithSignature
	inBuffer                   chan []byte
	outLock                    *sync.Mutex
	outPacketBuffer            []transport.FQDN

	privateKey *cryptography.PrivateKey
	remoteAddr DNSTAddr
	DNSSuffix  string
}

// ClientKeyConnID is a string composite type that's built with the client's public key string + the connection ID
// example: iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi40 + 41212 = iwtvpoygxxils8bc9ghss6nf6g0r67b7s4h88xik8c0vv3yi4041212
type ClientKeyConnID string

func (s *Server) deriveClientKeyConnID(payload *transport.MessagePacketWithSignature) ClientKeyConnID {
	return ClientKeyConnID(string(payload.Signature.String()) + string(payload.Msg.ConnID))
}

// implements net.Listener
type Server struct {
	Listener           net.PacketConn // DNS Tunnel works on top of a dns server (udp, tcp, tls, unix socket etc). The design is decoupled from the nature of the socket
	DNSSuffix          string         // top level suffix expected
	privateKey         *cryptography.PrivateKey
	acceptedClientKeys []*cryptography.PublicKey         // if not empty, only comms from these keys will be accepted
	clients            map[ClientKeyConnID]*clientStatus // list of current clients. key can't be the actual public key because golang doesn't support struct custom equal functions. need to use the string
	clientLock         sync.Mutex
	latestClient       chan *clientStatus
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
func ListenDNST(privateKey *cryptography.PrivateKey, listener net.PacketConn, dnsSuffix string, acceptedClientKeys ...*cryptography.PublicKey) (net.Listener, error) {
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
		clients:            make(map[ClientKeyConnID]*clientStatus),
		clientLock:         sync.Mutex{},
		latestClient:       make(chan *clientStatus, 1),
		dedupPrevMsgHash:   0,
		ctx:                context.Background(),
	}

	dns.HandleFunc(".", server.handleDNS)

	dnsServer := dns.Server{
		PacketConn: listener,
	}
	go dnsServer.ActivateAndServe()
	go server.cleanupDeadClients()
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
			slog.Warn("failed to decrypt incoming packet",
				"error", err)
			return
		}
		for _, payload := range payloads {
			// determine the direction of the traffic
			if payload.Msg.Metadata.IsServer2Client() {
				s.handleServerToClient(w, m, payload)
			}
			if payload.Msg.Metadata.IsClient2Server() {
				s.handleClientToServer(w, m, payload)
			}
			if payload.Msg.Metadata.IsClosing() {
				s.handleClosing(w, m, payload)
			}
		}
	}
}

func (s *Server) initiateNewClient(payload *transport.MessagePacketWithSignature) *clientStatus {
	k := s.deriveClientKeyConnID(payload)
	s.clientLock.Lock()

	s.clients[k] = &clientStatus{
		ConnID:                     payload.Msg.ConnID,
		LastAckFromAgentServerTime: uint32(time.Now().Unix()),
		LastAckFromAgentPacketTime: payload.Msg.TimeStamp,
		inPacketBuffer:             make([]transport.MessagePacketWithSignature, 0),
		inBuffer:                   make(chan []byte, 1),
		outLock:                    &sync.Mutex{},
		outPacketBuffer:            make([]transport.FQDN, 0),

		privateKey: s.privateKey,
		remoteAddr: DNSTAddr{pubKey: *payload.Signature},
		DNSSuffix:  s.DNSSuffix,
	}
	s.clientLock.Unlock()
	return s.clients[k]
}

// prepareEncryptedPong prepares a pong! message for the client
func (s *clientStatus) prepareEncryptedPong() transport.FQDN {
	metadata := transport.PacketMetaData(0).SetIsLastPart(true).SetIsClosing(true)

	cnames, _, err := transport.PreparePartitionedPayload(metadata, s.ConnID, []byte("pong!"), s.DNSSuffix, s.privateKey, &s.remoteAddr.pubKey)
	if err != nil {
		slog.Error("failed to prepare payload",
			"error", err)
	}
	return cnames[0]
}

func (s *Server) handleServerToClient(w dns.ResponseWriter, r *dns.Msg, emptyPayload transport.MessagePacketWithSignature) {
	// the payload should be empty, respond with a CNAME containing the intended payload buffer. if we have nothing to send, respond with a healthcheck
	var fqdn transport.FQDN
	k := s.deriveClientKeyConnID(&emptyPayload)
	// check to see if this is the first time we're seeing this client. TODO: should we just fail here and wait for a client to exist before sending data to it?
	if client, ok := s.clients[k]; !ok {
		// this would be a brand new healthcheck message coming from the client. healthchecks form the clients are actually
		// sent as server2client because their main purpose is to grab the data as CNAMEs in response
		client = s.initiateNewClient(&emptyPayload)
		s.latestClient <- client
		// if this is a new client, we don't have anything to send to it yet. so we'll respond with an empty CNAME
		fqdn = client.prepareEncryptedPong()
	} else {
		// pop the first item from the out buffer
		client.outLock.Lock()
		fqdn = client.outPacketBuffer[0]
		client.outPacketBuffer = client.outPacketBuffer[1:]
		client.outLock.Unlock()
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", r.Question[0].Name, fqdn))
	if err != nil {
		slog.Error("failed to create CNAME",
			"error", err)
	}
	r.Answer = append(r.Answer, cname)
	if err := w.WriteMsg(r); err != nil {
		slog.Warn("failed to write response",
			"error", err)
	}
}

func (s *Server) handleClientToServer(w dns.ResponseWriter, r *dns.Msg, payload transport.MessagePacketWithSignature) {
	// read the payload, decrypt and verify, and add it to the buffer for the client's public key
	k := s.deriveClientKeyConnID(&payload)
	// check to see if this is the first time we're seeing this client
	if client, ok := s.clients[k]; !ok {
		// since any "normal" client starts by sending a healthcheck, they should be already reigstered on the handleServer2Client function
		// and this should be a very rare case
		slog.Warn("client is sending a payload before sending a healthcheck")
		client = s.initiateNewClient(&payload)
		s.latestClient <- client
	} else {
		client.inPacketBuffer = append(client.inPacketBuffer, payload)
		if payload.Msg.Metadata.IsLastPart() {
			// order and clean up all the payloads
			packets := transport.CheckMessageIntegrity(client.inPacketBuffer)
			if packets == nil {
				// the payload does not have the last packet, we should return an empty payload and an error
				slog.Warn("failed to check message integrity")
			}
			for _, packet := range packets {
				packetPayload := packet.Msg.Payload[:]
				client.inBuffer <- packetPayload
			}
			client.inPacketBuffer = make([]transport.MessagePacketWithSignature, 0)
		}
	}

	cnames, _, err := transport.PreparePartitionedPayload(transport.PacketMetaData(0), payload.Msg.ConnID, []byte("pong!"), s.DNSSuffix, s.privateKey, payload.Signature)
	if err != nil {
		slog.Error("failed to prepare payload",
			"error", err)
	}
	cname, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", r.Question[0].Name, cnames[0]))
	if err != nil {
		slog.Error("failed to create CNAME",
			"error", err)
	}
	r.Answer = append(r.Answer, cname)
	if err := w.WriteMsg(r); err != nil {
		slog.Warn("failed to write response",
			"error", err)
	}

}

// handleClosing handles DNS packets that are coming in from the client that has the closing flag set.
func (s *Server) handleClosing(w dns.ResponseWriter, r *dns.Msg, payload transport.MessagePacketWithSignature) {
	// let's find the client first
	k := s.deriveClientKeyConnID(&payload)
	client, ok := s.clients[k]
	if !ok {
		slog.Warn("client is sending a closing packet but they don't exist anyway")
		return
	}
	// delete the client item
	delete(s.clients, k)
	client.Close()
}

// cleanupDeadClients deletes the clients that have been idle for too long
// this function should be called as a goroutine
func (s *Server) cleanupDeadClients() {
	ticker := time.NewTicker(defaultCleanupInterval)
	defer ticker.Stop()
	for {
		<-ticker.C
		for k, v := range s.clients {
			lastSeen := time.Unix(int64(v.LastAckFromAgentPacketTime), 0)
			if time.Since(lastSeen) > defaultCleanupInterval {
				delete(s.clients, k)
			}
		}
	}
}

func (s *Server) Close() error {
	return nil
}

func (s *Server) Addr() net.Addr {
	return &DNSTAddr{
		pubKey: s.privateKey.GetPublicKey(),
	}
}

func (s *Server) Accept() (net.Conn, error) {
	c := <-s.latestClient
	return c, nil
}

func (s *clientStatus) Read(b []byte) (n int, err error) {
	tmpBuf := <-s.inBuffer
	n = copy(b, tmpBuf)
	return
}

func (s *clientStatus) Write(b []byte) (n int, err error) {

	metadata := transport.PacketMetaData(0).SetIsServer2Client(true)

	fqdns, _, err := transport.PreparePartitionedPayload(metadata, s.ConnID, b, s.DNSSuffix, s.privateKey, &s.remoteAddr.pubKey)
	if err != nil {
		slog.Error("failed to prepare payload:",
			"error", err)
	}
	s.outLock.Lock()
	s.outPacketBuffer = append(s.outPacketBuffer, fqdns...)
	s.outLock.Unlock()
	return len(b), nil
}

func (s *clientStatus) Close() error {
	return nil
}
func (s *clientStatus) LocalAddr() net.Addr {
	return &DNSTAddr{pubKey: s.privateKey.GetPublicKey()}
}
func (s *clientStatus) RemoteAddr() net.Addr {
	return &s.remoteAddr
}
func (s *clientStatus) SetDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
func (s *clientStatus) SetReadDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
func (s *clientStatus) SetWriteDeadline(t time.Time) error {
	// TODO: implement
	return nil
}
