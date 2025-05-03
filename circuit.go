package rawnet

import (
	"log"
	"sync"
)

// Circuit is a L2 network that can accept multiple clients either L2 or L3.
// L3 clients will be assigned a random MAC address.
type VirtualCircuit struct {
	peers   map[L2Device]L2Device
	peersLk sync.RWMutex

	debug bool

	// TODO: add mac table
}

func NewCircuit() *VirtualCircuit {
	circ := &VirtualCircuit{
		peers: make(map[L2Device]L2Device),
	}

	return circ
}

func (c *VirtualCircuit) SetDebug(v bool) {
	c.debug = v
}

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

func (c *VirtualCircuit) BridgeDevice(dev L2Device) error {
	c.peersLk.Lock()
	defer c.peersLk.Unlock()

	c.peers[dev] = dev

	return nil
}
