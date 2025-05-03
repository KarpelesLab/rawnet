package rawnet

import "fmt"

type L4Proto uint8

const (
	L4ICMP L4Proto = 0x01
	L4TCP  L4Proto = 0x06
	L4UDP  L4Proto = 0x11
)

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

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
	case 0x3a:
		return ParseICMP6(data)
	}
	return InvalidFrame(data), fmt.Errorf("unsupported layer4 type %x", t)
}
