package transport

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lunixbochs/struc"
	"github.com/miekg/dns"
	"github.com/mosajjal/dnsconn/cryptography"
)

const (
	// PayloadSize is the maximum number of bytes that can be fit inside a C2 Msg object. it will have the added headers before being sent on wire
	PayloadSize = int(70)
	// ChunkSize determines how much data each DNS query or response has. after converting the msg of ChunkSize to base32, it shouldn't exceed ~250 bytes
	ChunkSize = uint8(90)
	// CompressionThreshold sets the minimum msg size to be compressed. anything lower than this size will be sent uncompressed
	CompressionThreshold = 1024 * 2 // 2KB
)

// PartID is the ID of each part of a multipart message.
type PartID uint16
type ConnID uint16

type PacketMetaData uint8

// FQDN would be the actual A query or CNAME response that is sent over the wire
type FQDN string

func (p PacketMetaData) IsClient2Server() bool {
	return p&IsClient2Server == IsClient2Server
}
func (p PacketMetaData) IsServer2Client() bool {
	return p&IsServer2Client == IsServer2Client
}
func (p PacketMetaData) IsLastPart() bool {
	return p&IsLastPart == IsLastPart
}
func (p PacketMetaData) IsKeepAlive() bool {
	return p&IsKeepAlive == IsKeepAlive
}
func (p PacketMetaData) IsClosing() bool {
	return p&IsClosing == IsClosing
}

func (p PacketMetaData) SetIsClient2Server(isSend bool) PacketMetaData {
	if isSend {
		p |= IsClient2Server
	} else {
		p &= ^IsClient2Server
	}
	return p
}
func (p PacketMetaData) SetIsServer2Client(isReceive bool) PacketMetaData {
	if isReceive {
		p |= IsServer2Client
	} else {
		p &= ^IsServer2Client
	}
	return p
}
func (p PacketMetaData) SetIsLastPart(isLastPart bool) PacketMetaData {
	if isLastPart {
		p |= IsLastPart
	} else {
		p &= ^IsLastPart
	}
	return p
}
func (p PacketMetaData) SetIsKeepAlive(isKeepAlive bool) PacketMetaData {
	if isKeepAlive {
		p |= IsKeepAlive
	} else {
		p &= ^IsKeepAlive
	}
	return p
}
func (p PacketMetaData) SetIsClosing(isClosing bool) PacketMetaData {
	if isClosing {
		p |= IsClosing
	} else {
		p &= ^IsClosing
	}
	return p
}

const (
	NoMetadata      PacketMetaData = 0
	IsClient2Server PacketMetaData = 1 << 0
	IsServer2Client PacketMetaData = 1 << 1
	IsLastPart      PacketMetaData = 1 << 2
	IsKeepAlive     PacketMetaData = 1 << 3
	IsClosing       PacketMetaData = 1 << 4
)

// MessagePacket is the payload that gets (optionally) compressed, encrypted and the resulting payload
// will be on the wire for each DNS query and response
type MessagePacket struct {
	TimeStamp     uint32         `struc:"uint32,little"`
	PartID        PartID         `struc:"uint16,little"`
	ConnID        ConnID         `struc:"uint16,little"`
	Metadata      PacketMetaData `struc:"uint8,little"`
	PayloadLength uint8          `struc:"uint8,little,sizeof=Payload"`
	Payload       []byte         `struc:"[]byte,little"`
}

// MessagePacketWithSignature adds Signature to each packet separetely to help with reconstruction of packets
type MessagePacketWithSignature struct {
	Signature *cryptography.PublicKey
	Msg       MessagePacket
}

// since the comms channel for DNS is out of our hands, we need to implement a dedup method for any bytestream
type dedup map[uint64]struct{}

var dedupRWLock = &sync.RWMutex{}

// Add function gets a byte array and adds it to the dedup table. returns true if the key is new, false if it already exists
func (d *dedup) Add(keyBytes []byte) bool {
	//calculate FNV1A
	dedupRWLock.Lock()
	key := FNV1A(keyBytes)
	if _, ok := (*d)[key]; ok {
		return false
	}
	(*d)[key] = struct{}{}
	dedupRWLock.Unlock()
	return true
}

// DedupHashTable is an empty map with the hash of the payload as key.
var DedupHashTable dedup = make(map[uint64]struct{})

// PerformExternalAQuery is a very basic A query provider. TODO: this needs to move to github.com/mosajjal/dnsclient
func PerformExternalAQuery(Q FQDN, server net.Addr) (*dns.Msg, error) {
	question := dns.Question{Name: string(Q), Qtype: dns.TypeA, Qclass: dns.ClassINET}
	c := new(dns.Client)
	c.Timeout = 6 * time.Second //todo: make this part of config
	m1 := new(dns.Msg)
	m1.Compress = true
	m1.SetEdns0(1500, false)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = question
	in, _, err := c.Exchange(m1, server.String())
	return in, err
}

// inserNth takes a string and inserts a dot char every nth char.
// returns the number of dots inserted, plus the modified string
// example: insertNth("1234567890", 3) => "123.456.789.0.3"
func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	numberOfDots := 0
	var n1 = n - 1
	var l1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n1 && i != l1 {
			numberOfDots++
			buffer.WriteByte('.') //dot char in DNS
		}
	}
	// write number of dots to the end of the string
	// TODO: there's a small chance that the last char is a dot, which makes this a double dot. fix this
	buffer.WriteByte('.')
	buffer.WriteString(fmt.Sprintf("%d", numberOfDots))
	return buffer.String()
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func mustGZIP(in []byte) []byte {
	var b bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if _, err := gz.Write(in); err != nil {
		return nil
	}
	if err := gz.Flush(); err != nil {
		return nil
	}
	if err := gz.Close(); err != nil {
		return nil
	}
	return b.Bytes()
}

// PreparePartitionedPayload Gets a payload with arbitrary length that needs to be sent over the wire.
// based on the const config items, it will split the payload to smaller parts and creates a
// list of FQDNs to be sent over the wire. It also returns the ConnID to make sure the series of messages are not lost
func PreparePartitionedPayload(msgMetadata PacketMetaData, msgConnID ConnID, payload []byte, dnsSuffix string, privateKey *cryptography.PrivateKey, serverPublicKey *cryptography.PublicKey) ([]FQDN, ConnID, error) {
	// TODO: fix duplicate sending
	// handle compression
	if len(payload) > CompressionThreshold {
		payload = mustGZIP(payload)
		if payload == nil {
			return nil, msgConnID, errors.New("failed to compress payload")
		}
	}

	var response []FQDN
	msg := MessagePacket{
		TimeStamp: uint32(time.Now().Unix()),
		ConnID:    msgConnID,
		Metadata:  msgMetadata,
	}
	msg.Metadata = msg.Metadata.SetIsLastPart(true) // if the message is only one part, the last part is always true
	// retryCount := 1 //todo: retry of >1 could cause message duplicates
	msgParts := split(payload, int(ChunkSize))
	if len(msgParts) > 1 {
		// if the message is more than one part, the first part is never the last part
		msg.Metadata = msg.Metadata.SetIsLastPart(false)
		msg.PartID = 0
	}
	//todo: maybe a cap on the number of limbs here, as well as some progress logging inside the loop?
	// looping over the msgparts, encrypting the payload and creating the FQDN
	for i := 0; i < len(msgParts); i++ {
		if i == len(msgParts)-1 && len(msgParts) > 1 {
			msg.Metadata = msg.Metadata.SetIsLastPart(true)
		}
		// msg.Payload = []byte{}
		// msg.PayloadLength = uint8(copy(msg.Payload[:], limbs[i]))
		msg.Payload = msgParts[i]
		msg.PayloadLength = uint8(len(msgParts[i]))
		var buf bytes.Buffer
		buf.Reset()
		if err := struc.Pack(&buf, &msg); err != nil {
			return response, msg.ConnID, err
		}
		// fmt.Printf("sending: %#+v\n", msg) //todo: remove
		encrypted, err := privateKey.Encrypt(serverPublicKey, buf.Bytes())
		if err != nil {
			return response, msg.ConnID, err
		}

		s := cryptography.EncodeBytes(encrypted)

		// as per DNS specification, the maximum length of a subdomain is 64 characters
		fqdn := insertNth(s, 63)
		response = append(response, FQDN(fqdn+dnsSuffix))
		msg.PartID++
	}
	return response, msg.ConnID, nil
}

// getSubdomainsFromDNSMessage parses a dns message and converts it into a list of FQDNs
// given the design of dnsConn, only A queries and CNAME responses are expected
// since standard DNS clients return the question as part of a response message, we need to be able to
// discard the question when there's answer RR in the msg
func getSubdomainsFromDNSMessage(m *dns.Msg) []string {
	var res []string
	if len(m.Answer) > 0 {
		// for _, a := range m.Answer {
		// 	res = append(res, a.String())
		// }
		res1, _ := m.Answer[0].(*dns.CNAME)
		res = append(res, res1.Target)
	} else {
		for _, q := range m.Question {
			res = append(res, q.Name)
		}
	}
	return res
}

// DecryptIncomingPacket decrypts the incoming packet and returns the list of messages, a boolean indicating if the message should be skipped, and an error.
// note that in the current implementation, MessagePacketWithSignature is a list of one
func DecryptIncomingPacket(m *dns.Msg, suffix string, privatekey *cryptography.PrivateKey, publickey *cryptography.PublicKey) ([]MessagePacketWithSignature, bool, error) {
	out := []MessagePacketWithSignature{}
	// in the current implementation, each request or response is only one A/CNAME record
	// so we expect this list to be of length 1, however, this function ignores this fact
	// and loops anyway.
	listOfSubdomains := getSubdomainsFromDNSMessage(m)
	for _, sub := range listOfSubdomains {
		if strings.HasSuffix(sub, suffix) {

			// verify incoming domain
			requestWithoutSuffix := strings.TrimSuffix(sub, suffix)
			if sub == requestWithoutSuffix {
				return out, true, errors.New("request does not have the correct suffix")
			}

			// remove the number of dots from FQDN
			lastSubdomainIndex := strings.LastIndex(requestWithoutSuffix, ".")
			if lastSubdomainIndex == -1 { // if there is no dot, then the request is invalid
				return out, true, fmt.Errorf("incomplete DNS request %s", requestWithoutSuffix)
			}
			numberOfDots := requestWithoutSuffix[lastSubdomainIndex+1:]
			requestWithoutSuffix = requestWithoutSuffix[:lastSubdomainIndex]

			dotCount := strings.Count(requestWithoutSuffix, ".")
			// the reason why dotcount is being checked is when a client asks for A.B.C.domain.com from 1.1.1.1 with the suffix of domain.com,
			// 1.1.1.1 sends C.domain.com first, then B.C.domain.com and then the full request
			// since anything other than A.B.C is invalid, we can skip the first two requests, which we do by checking the number of dots in the request
			if fmt.Sprint(dotCount) != numberOfDots {
				return out, true, fmt.Errorf("subdomain count mismatch. expected %s, got %d", numberOfDots, dotCount)
			}

			msgRaw := strings.Replace(requestWithoutSuffix, ".", "", -1)
			// // padding
			// if i := len(msgRaw) % 8; i != 0 {
			// 	msgRaw += strings.Repeat("=", 8-i)
			// }

			msg := cryptography.DecodeToBytes(msgRaw)

			// check duplicate msg
			if !DedupHashTable.Add(msg) {
				return out, true, fmt.Errorf("duplicate message")
			}
			var decrypted []byte
			var err error
			if publickey == nil {
				decrypted, err = privatekey.Decrypt(msg)
				if err != nil {
					return out, false, err
				}
			} else {
				decrypted, err = privatekey.DecryptAndVerify(msg, publickey)
			}
			if err != nil {
				//todo: since a lot of these are noise and duplicates, maybe we can skip putting this as error
				// when a DNS client sends a request like a.b.c.d.myc2.com, some recurisve DNS
				// server don't pass that on to the NS server. instead, they start by sending
				// d.myc2.com, then c.d.myc2.com and so on, making our job quite difficult
				return out, false, err
			}

			o := MessagePacketWithSignature{}
			o.Signature = cryptography.GetPublicKeyFromMessage(msg)
			err = struc.Unpack(bytes.NewBuffer(decrypted), &o.Msg)
			if err != nil {
				return out, false, errors.New("couldn't unpack message")
			}
			out = append(out, o)
		}
	}
	return out, false, nil
}

// CheckMessageIntegrity gets a list of packets with their signatures
// and returns another packet list that are sorted, deduplicated and are complete
func CheckMessageIntegrity(packets []MessagePacketWithSignature) []MessagePacketWithSignature {
	//sort, uniq and remove duplicates. then check if the message is complete
	if len(packets) == 0 {
		return nil
	}

	//sort
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].Msg.PartID < packets[j].Msg.PartID
	})

	// unique
	for i := 0; i < len(packets)-1; i++ {
		if packets[i].Msg.PartID == packets[i+1].Msg.PartID {
			packets = append(packets[:i], packets[i+1:]...)
			i--
		}
	}
	// check if the message is complete
	if len(packets) == int(packets[len(packets)-1].Msg.PartID)+1 {
		return packets
	}
	return nil
}

// FNV1A a very fast hashing function, mainly used for de-duplication
func FNV1A(input []byte) uint64 {
	var hash uint64 = 0xcbf29ce484222325
	var fnvPrime uint64 = 0x100000001b3
	for _, b := range input {
		hash ^= uint64(b)
		hash *= fnvPrime
	}
	return hash
}
