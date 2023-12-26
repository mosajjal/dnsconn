package dnsconn

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mosajjal/dnsconn/cryptography"
	"github.com/mosajjal/dnsconn/transport"
)

// implements net.Conn
type client struct {
	// transport related fields
	privateKey      *cryptography.PrivateKey // private key of the client for decrypting and signing the messages
	serverPublicKey *cryptography.PublicKey  // public key of the server for verifying the signature of the messages and encrypting the payload
	dnsSuffix       string                   // the dns suffix of the server. each message sent will be a random string with this suffix at the end
	resolver        net.Addr                 // DNS resolver to use to make the A queries over. currently, only plain UDP is supported. TODO: add encrypted DNS

	// read related fields
	timeout       time.Duration                                               // used in the startRead goroutine to make sure to close the connections that don't have a response from the server whatsoever
	readInterval  time.Duration                                               // used in the startRead goroutine to configure the interval between sending read requests
	readPacketBuf map[transport.PartID][]transport.MessagePacketWithSignature // buffer for incoming DNS packets so we can re-order and dedup before pushing to the actual bytes array
	readBuf       []byte                                                      // raw bytes buffer. TODO: add max size
	readCtx       context.Context                                             // used in Read function when setReadDeadline is used
	readLock      sync.Mutex                                                  // used to lock the readBuf
	connected     chan struct{}

	// write related fields
	writeBuf  []byte          // outgoing buffer
	writeCtx  context.Context // used in Write function when setWriteDeadline is used
	writeLock sync.Mutex      // used to lock the writeBuf
}

// grabFullPayload tries to reconstruct the incoming buffer into a single payload. cleans the buffer if successful
func (c *client) grabFullPayload(parentPartID transport.PartID) ([]byte, error) {
	fullPayload := make([]byte, 0)
	packets := transport.CheckMessageIntegrity(c.readPacketBuf[parentPartID])
	if packets == nil {
		// the payload does not have the last packet, we should return an empty payload and an error
		return fullPayload, fmt.Errorf("the payload does not have the last packet yet")
	}
	for _, packet := range packets {
		packetPayload := packet.Msg.Payload[:]
		fullPayload = append(fullPayload, packetPayload...)
	}
	delete(c.readPacketBuf, packets[0].Msg.ParentPartID)
	// assuming this is the last part and we're going back to the normal interval
	c.readInterval = 2 * time.Second
	return bytes.Trim(fullPayload, "\x00"), nil

}

func (c *client) sendQuestionToServer(Q transport.FQDN) error {
	if len(Q) > 255 {
		return fmt.Errorf("query is too big %d, can't send this", len(Q))
	}

	response, err := transport.PerformExternalAQuery(Q, c.resolver) //currently, only plain DNS is supported. TODO: add encrypted DNS
	if err != nil {
		return fmt.Errorf("failed to send the payload: %s", err)
	}
	msgList, skip, err := transport.DecryptIncomingPacket(response, c.dnsSuffix, c.privateKey, c.serverPublicKey)
	if err != nil {
		return fmt.Errorf("error in decrypting incoming packet from server: %s", err)
	} else if !skip {
		// if we're not skipping, and there's an actual payload from the server, we need to check if it's a multipart or not. if it is
		// we will lower our interval to make sure we get all the data as fast as possible till we see the last part. then we'll revert
		// back to the normal interval

		parentPartID := transport.PartID(0)
		// push the messages one by one to readPacketBuf based on their parent part id
		for _, msg := range msgList {
			if _, ok := c.readPacketBuf[msg.Msg.ParentPartID]; !ok {
				c.readPacketBuf[msg.Msg.ParentPartID] = make([]transport.MessagePacketWithSignature, 0)
				c.readLock.Lock()
			}

			// if the incoming packet is a result of client sending to the server, the CNAME returned is just a "pong" acknowledgement
			// so we'll focus on only server to client packets that actuallly have useful data in the CNAME payload
			if msgList[0].Msg.Metadata.IsServer2Client() {
				c.readInterval = 50 * time.Millisecond // speed things up because tehre's a next message coming in
				c.readPacketBuf[msg.Msg.ParentPartID] = append(c.readPacketBuf[msg.Msg.ParentPartID], msg)
				if parentPartID == 0 {
					parentPartID = msg.Msg.ParentPartID
				}
			}

			// if the packet from the server is the last part, we can start reconstructing the payload
			if msg.Msg.Metadata.IsLastPart() {
				if incomingPayload, err := c.grabFullPayload(parentPartID); err == nil {
					c.readBuf = append(c.readBuf, incomingPayload...)
					c.readLock.Unlock()
				}
				// this is where the Read() function can stop blocking
			}
		}

	}

	return nil
}

// DialDNST creates a new DNS Tunnel client. It will return a net.PacketConn that can be used to send and receive any arbitrary payload
// parameters:
//   - privateKey: the private key of the agent. can be empty. in which case, a new private key will be generated on the fly
//   - serverPublicKey: the public key of the server. cannot be empty
//   - DNSSuffix: the DNS suffix of the server. cannot be empty and MUST have a trailing and leading dot
//   - resolver: the address of the DNS server to send the queries to. can be nil in which case OS's default resolver will be used
func DialDNST(privateKey *cryptography.PrivateKey, serverPublicKey *cryptography.PublicKey, DNSSuffix string, resolver net.Addr) net.Conn {
	if privateKey == nil {
		// generate a new private key
		privateKey, _ = cryptography.GenerateKey()
	}

	client := &client{
		timeout:         10 * time.Second,
		privateKey:      privateKey,
		serverPublicKey: serverPublicKey,
		dnsSuffix:       DNSSuffix,
		resolver:        resolver,
	}
	client.readPacketBuf = make(map[transport.PartID][]transport.MessagePacketWithSignature)
	client.readBuf = make([]byte, 0)
	client.readCtx = context.Background()
	client.readLock = sync.Mutex{}
	client.readInterval = 1 * time.Second

	client.writeBuf = make([]byte, 0)
	client.writeCtx = context.Background()
	client.writeLock = sync.Mutex{}
	client.connected = make(chan struct{}, 1)

	go client.startRead()
	go client.startWrite()
	// BUG: client won't want and just quits on this
	<-client.connected
	return client

}

// startWrite is a goroutine that will continuously write the buffer to the server if it's not empty
func (c *client) startWrite() {
	for {
		select {
		case <-c.writeCtx.Done():
			msg := transport.MessagePacket{
				TimeStamp: uint32(time.Now().Unix()),
				Metadata:  transport.PacketMetaData(0),
			}
			msg.Metadata = msg.Metadata.SetIsClosing(true)
			payload := []byte("closing!")
			// we expect questions to be an array of one, since the payload is empty
			questions, _, err := transport.PreparePartitionedPayload(msg, payload, c.dnsSuffix, c.privateKey, c.serverPublicKey)
			if err != nil {
				slog.Error("failed to prepare payload",
					"error", err)
			}
			// send the close payload to the server
			err = c.sendQuestionToServer(questions[0])
			if err != nil {
				slog.Error("failed to send close payload",
					"error", err)
			}
			return
		default:
			c.writeLock.Lock()
			if len(c.writeBuf) > 0 {
				// write the buffer to the server and clear the buffer
				msg := transport.MessagePacket{
					TimeStamp: uint32(time.Now().Unix()),
					Metadata:  transport.PacketMetaData(0),
				}
				msg.Metadata = msg.Metadata.SetIsClient2Server(true)
				questions, _, err := transport.PreparePartitionedPayload(msg, c.writeBuf, c.dnsSuffix, c.privateKey, c.serverPublicKey)
				if err != nil {
					slog.Error("failed to prepare payload",
						"error", err)
				}
				for _, question := range questions {
					err := c.sendQuestionToServer(question)
					if err != nil {
						slog.Error("failed to send question",
							"error", err)
					}
				}
				c.writeBuf = make([]byte, 0)
			}
			c.writeLock.Unlock()
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// startRead starts a goroutine that sends healthchecks to the server. the server can send the payload as CNAME response to the healthchecks
// if there's any data recieved, it'll be stored inside a buffer and will be passed on to the Read function as a FIFO
func (c *client) startRead() {
	ticker := time.NewTicker(c.readInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.readCtx.Done():
			return
		case <-ticker.C:
			msg := transport.MessagePacket{
				TimeStamp: uint32(time.Now().Unix()),
				Metadata:  transport.PacketMetaData(0),
			}
			msg.Metadata = msg.Metadata.SetIsKeepAlive(true)
			msg.Metadata = msg.Metadata.SetIsServer2Client(true)
			payload := []byte("ping!")
			// we expect questions to be an array of one, since the payload is empty
			questions, _, err := transport.PreparePartitionedPayload(msg, payload, c.dnsSuffix, c.privateKey, c.serverPublicKey)
			if err != nil {
				slog.Error("failed to prepare payload",
					"error", err)
			}
			// send the healthcheck to the server. the response of this has the server payload inside of it.
			err = c.sendQuestionToServer(questions[0])
			if err != nil {
				slog.Error("failed to send healthcheck",
					"error", err)
			}
			c.connected <- struct{}{}
		}
	}
}

// ReadFrom checks the buffer and returns everything inside it. the buffer is then flushed
func (c *client) Read(b []byte) (n int, err error) {
	c.readLock.Lock()
	defer c.readLock.Unlock()
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]

	return
}

// WriteTo sends the payload to the server as series of DNS A queries
// addr is ignored and is always replaced by the server's public key
func (c *client) Write(b []byte) (n int, err error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	c.writeBuf = append(c.writeBuf, b...)
	return len(b), nil
}

// Close cleans up the connection by sending a IsClosing payload. TODO: implement
func (c *client) Close() error {
	c.writeCtx.Done()
	c.readCtx.Done()
	return nil
}

// LocalAddr returns the local network address
func (c *client) LocalAddr() net.Addr {
	return &DNSTAddr{pubKey: c.privateKey.GetPublicKey()}
}

func (c *client) RemoteAddr() net.Addr {
	return &DNSTAddr{pubKey: *c.serverPublicKey}
}

func (c *client) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *client) SetReadDeadline(t time.Time) error {
	var cancel context.CancelFunc
	c.readCtx, cancel = context.WithDeadline(c.readCtx, t)
	defer cancel()
	return nil
}

func (c *client) SetWriteDeadline(t time.Time) error {
	var cancel context.CancelFunc
	c.writeCtx, cancel = context.WithDeadline(c.writeCtx, t)
	defer cancel()
	return nil
}
