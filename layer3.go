package rawnet

import "fmt"

//go:generate stringer -type=Protocol

type Protocol uint16

const (
	ProtoIPv4 Protocol = 0x0800
	ProtoIPv6 Protocol = 0x86dd
	ProtoARP  Protocol = 0x0806
	ProtoRARP Protocol = 0x8035
	ProtoXNS  Protocol = 0x0600
	ProtoVLAN Protocol = 0x8100
)

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
