package rawnet

import (
	"crypto/rand"
	"io"
	"log"
	"net"
)

type Circuit interface {
	L2Device
	BridgeDevice(dev L2Device) error
}

type L2Device interface {
	HandleL2Packet(src L2Device, pkt L2Packet) error
}

type L3Device interface {
	HandleL3Packet(Protocol, L3Packet) error
}

type BaseL3 struct {
	mac net.HardwareAddr
}

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

func (b *BaseL3) HandleL2Packet(p L3Packet) error {
	log.Printf("[rawnet] Sample L3 device received %d bytes packet", len(p))
	return nil
}
