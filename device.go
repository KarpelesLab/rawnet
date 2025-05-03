// Package rawnet provides tools for low-level network packet manipulation
// at layers 2, 3, and 4 of the OSI model.
package rawnet

import (
	"crypto/rand"
	"io"
	"log"
	"net"
)

// Circuit represents a virtual network circuit that can connect multiple devices.
// It acts as a virtual switch or hub that can bridge Layer 2 devices together.
type Circuit interface {
	L2Device
	BridgeDevice(dev L2Device) error
}

// L2Device represents a Layer 2 network device that can handle Ethernet frames.
// This interface is implemented by any device that operates at the data link layer.
type L2Device interface {
	HandleL2Packet(src L2Device, pkt L2Packet) error
}

// L3Device represents a Layer 3 network device that can handle IP packets.
// This interface is implemented by routers and other devices that operate at the network layer.
type L3Device interface {
	HandleL3Packet(Protocol, L3Packet) error
}

// BaseL3 provides a basic implementation for Layer 3 devices.
// It contains a MAC address for the virtual L3 device.
type BaseL3 struct {
	mac net.HardwareAddr
}

// NewBaseL3 creates a new BaseL3 instance with a randomly generated MAC address.
// It can be used as a foundation for implementing L3Device interfaces.
func NewBaseL3(d L2Device) (*BaseL3, error) {
	macAddr := make([]byte, 6)
	_, err := io.ReadFull(rand.Reader, macAddr)
	if err != nil {
		return nil, err
	}

	res := new(BaseL3)
	res.mac = net.HardwareAddr(macAddr)

	return res, nil
}

// HandleL2Packet implements a basic packet handler for L3 devices.
// This is a sample implementation that logs the packet size.
func (b *BaseL3) HandleL2Packet(p L3Packet) error {
	log.Printf("[rawnet] Sample L3 device received %d bytes packet", len(p))
	return nil
}
