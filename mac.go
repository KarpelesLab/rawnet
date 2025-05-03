package rawnet

import (
	"crypto/rand"
	"io"
	"net"
)

type HardwareAddr [6]byte

// NewHardwareAddr() will generate a new hardware address suitable for private use
func NewHardwareAddr() (net.HardwareAddr, error) {
	macAddr := make([]byte, 6)
	_, err := io.ReadFull(rand.Reader, macAddr)
	if err != nil {
		return nil, err
	}

	// set bits of first byte so it is xxxxxx10 (locally administered, unicast)
	macAddr[0] = (macAddr[0] & 0xfc) | 0x02

	return macAddr, nil
}
