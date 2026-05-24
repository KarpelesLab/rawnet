package rawnet

import (
	"log"
	"sync"
)

// VirtualCircuit implements a Layer 2 network that can accept multiple clients (L2 or L3).
// It acts as a virtual switch or hub, broadcasting packets to all connected devices.
// L3 clients will be assigned a random MAC address when connected.
//
// Deprecated: use pktkit.L2Hub from github.com/KarpelesLab/pktkit instead.
// pktkit.L2Hub learns source MACs and forwards unicast frames to the correct
// port rather than flooding every frame.
type VirtualCircuit struct {
	peers   map[L2Device]L2Device
	peersLk sync.RWMutex

	debug bool

	// TODO: add mac table
}

// NewCircuit creates a new VirtualCircuit instance.
// This circuit can have multiple L2 devices attached to it via BridgeDevice.
//
// Deprecated: use pktkit.NewL2Hub from github.com/KarpelesLab/pktkit instead,
// which provides MAC learning and is the supported replacement for
// VirtualCircuit.
func NewCircuit() *VirtualCircuit {
	circ := &VirtualCircuit{
		peers: make(map[L2Device]L2Device),
	}

	return circ
}

// SetDebug enables or disables debug logging for this circuit.
// When enabled, the circuit will log information about packet handling.
func (c *VirtualCircuit) SetDebug(v bool) {
	c.debug = v
}

// HandleL2Packet implements the L2Device interface.
// It broadcasts the received packet to all connected devices except the source.
// For circuits with more than 16 devices, it uses goroutines for parallel delivery.
func (c *VirtualCircuit) HandleL2Packet(src L2Device, pkt L2Packet) error {
	// handle packet. Everything broadcast!
	// TODO: check pkt source ethernet address and source device, and if directly connected store in mac table for unicast processing

	if c.debug {
		log.Printf("[circuit] packet from %T: %s", src, pkt.GetEthertype())
	}

	// multicast / broadcast
	c.peersLk.RLock()

	// if not too many devices, stay in the same thread
	if len(c.peers) <= 16 {
		for _, dev := range c.peers {
			if dev != src {
				dev.HandleL2Packet(c, pkt)
			}
		}
		return nil
	}

	// If you have more than 16 devices in a virtual circuit, you should use a more optimized version of this.
	// We can build something that uses a ring buffer and sync.Cond similar to how KLab/ringbuf works

	var wg sync.WaitGroup
	// use a waitgroup so the pkt buffer will not be released until all peers have finished using it
	wg.Add(len(c.peers))
	for _, dev := range c.peers {
		if dev == src {
			//log.Printf("not sending packet to %T (source)", dev)
			wg.Done()
			continue
		}
		go func(p L2Device) {
			//log.Printf("sending packet to %T", dev)
			p.HandleL2Packet(c, pkt)
			wg.Done()
		}(dev)
	}
	c.peersLk.RUnlock()
	wg.Wait()
	return nil
}

// BridgeDevice connects a Layer 2 device to this circuit.
// All packets received by the circuit will be forwarded to this device,
// and all packets sent by this device will be broadcast to other devices.
func (c *VirtualCircuit) BridgeDevice(dev L2Device) error {
	c.peersLk.Lock()
	defer c.peersLk.Unlock()

	c.peers[dev] = dev

	return nil
}
