package rawnet

import "fmt"

//go:generate stringer -type=Protocol

// Protocol represents an EtherType value identifying network layer protocols.
// These values are used in Ethernet frames to indicate the type of the encapsulated protocol.
type Protocol uint16

// Standard EtherType values for common Layer 3 protocols
const (
	ProtoIPv4 Protocol = 0x0800 // IPv4 protocol
	ProtoIPv6 Protocol = 0x86dd // IPv6 protocol
	ProtoARP  Protocol = 0x0806 // Address Resolution Protocol
	ProtoRARP Protocol = 0x8035 // Reverse Address Resolution Protocol
	ProtoXNS  Protocol = 0x0600 // Xerox Network Systems
	ProtoVLAN Protocol = 0x8100 // IEEE 802.1Q VLAN tagging
)

// ParseLayer3 parses a Layer 3 packet based on its protocol identifier.
// It returns the appropriate Frame implementation for the given protocol.
// If the protocol is not supported, it returns an InvalidFrame.
func ParseLayer3(t Protocol, data []byte) (Frame, error) {
	switch t {
	case ProtoIPv4:
		return ParseIPv4(data)
	case ProtoIPv6:
		return ParseIPv6(data)
	case ProtoARP: // ARP
	case ProtoRARP: // RARP
	case ProtoXNS: // XNS
	}
	return InvalidFrame(data), fmt.Errorf("unsupported layer3 frame type %x", t)
}
