package rawnet

import "errors"

// IPFrame extends the Frame interface with methods specific to IP packets.
// It represents both IPv4 and IPv6 frames and provides access to encapsulated protocols.
type IPFrame interface {
	Frame

	// GetInner returns the encapsulated Frame (e.g., TCP, UDP) contained in this IP packet
	GetInner() Frame
}

// ParseIP examines an IP packet and determines whether it's IPv4 or IPv6.
// It then delegates to the appropriate protocol-specific parser.
// The function returns an error if the IP version is not recognized (not 4 or 6).
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
