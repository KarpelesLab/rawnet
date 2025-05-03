package rawnet

import "errors"

type IPFrame interface {
	Frame

	GetInner() Frame
}

func ParseIP(data []byte) (IPFrame, error) {
	// detect if ipv4 or ipv6
	ip_version := data[0] >> 4

	switch ip_version {
	case 4:
		return ParseIPv4(data)
	case 6:
		return ParseIPv6(data)
	default:
		return nil, errors.New("unknown IP version in packet")
	}
}
