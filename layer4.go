package rawnet

import "fmt"

// L4Proto represents an IP protocol number identifying transport layer protocols.
// These values are used in IP headers to indicate the type of the transport protocol.
// Reference: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
type L4Proto uint8

// Standard IP protocol numbers for common Layer 4 protocols
const (
	L4ICMP L4Proto = 0x01 // Internet Control Message Protocol (IPv4)
	L4TCP  L4Proto = 0x06 // Transmission Control Protocol
	L4UDP  L4Proto = 0x11 // User Datagram Protocol
)

// ParseLayer4 parses a Layer 4 packet based on its protocol identifier.
// It returns the appropriate Frame implementation for the given protocol.
// If the protocol is not supported, it returns an InvalidFrame.
func ParseLayer4(t L4Proto, data []byte) (Frame, error) {
	switch t {
	case L4ICMP: // icmp
		return ParseICMP(data)
	case 0x02: // igmp
		return ParseIGMP(data)
	case L4TCP: // tcp
		return ParseTCP(data)
	case L4UDP: // udp
		return ParseUDP(data)
	case 0x3a: // icmp6
		return ParseICMP6(data)
	}
	return InvalidFrame(data), fmt.Errorf("unsupported layer4 type %x", t)
}
