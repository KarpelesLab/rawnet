// Package rawnet provides tools for low-level network packet manipulation
// at layers 2, 3, and 4 of the OSI model.
//
// Deprecated: rawnet is no longer maintained. Use
// github.com/KarpelesLab/pktkit instead, which is a rewrite with a zero-copy
// data plane, a MAC-learning L2 hub, IP routing, DHCP, NAT, WireGuard,
// OpenVPN, TUN/TAP, QEMU, and a userspace NAT stack. See the README for a
// migration guide.
package rawnet

import (
	"crypto/rand"
	"io"
	"log"
	"net"
)

// Circuit represents a virtual network circuit that can connect multiple devices.
// It acts as a virtual switch or hub that can bridge Layer 2 devices together.
//
// Deprecated: use pktkit.L2Hub from github.com/KarpelesLab/pktkit instead.
type Circuit interface {
	L2Device
	BridgeDevice(dev L2Device) error
}

// L2Device represents a Layer 2 network device that can handle Ethernet frames.
// This interface is implemented by any device that operates at the data link layer.
//
// Deprecated: use pktkit.L2Device from github.com/KarpelesLab/pktkit, which
// uses a callback-based Send/SetHandler API and zero-copy Frame values.
type L2Device interface {
	HandleL2Packet(src L2Device, pkt L2Packet) error
}

// L3Device represents a Layer 3 network device that can handle IP packets.
// This interface is implemented by routers and other devices that operate at the network layer.
//
// Deprecated: use pktkit.L3Device from github.com/KarpelesLab/pktkit, which
// uses a callback-based Send/SetHandler API and zero-copy Packet values.
type L3Device interface {
	HandleL3Packet(Protocol, L3Packet) error
}

// BaseL3 provides a basic implementation for Layer 3 devices.
// It contains a MAC address for the virtual L3 device.
//
// Deprecated: use pktkit.L2Adapter from github.com/KarpelesLab/pktkit to
// bridge an L3 device onto an L2 network; it handles ARP, NDP, DHCP and
// gateway routing.
type BaseL3 struct {
	mac net.HardwareAddr
}

// NewBaseL3 creates a new BaseL3 instance with a randomly generated MAC address.
// It can be used as a foundation for implementing L3Device interfaces.
//
// Deprecated: use pktkit.NewL2Adapter from github.com/KarpelesLab/pktkit.
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
