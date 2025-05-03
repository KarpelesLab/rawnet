package rawnet

import (
	"fmt"
	"net"
)

type Ethernet struct {
	Dst net.HardwareAddr
	Src net.HardwareAddr

	EtherType Protocol
	VLan      uint16

	Len int

	Inner Frame
}

func (e *Ethernet) String() string {
	return fmt.Sprintf("ethernet(%v->%v)[%v]", e.Src, e.Dst, e.Inner)
}

func (e *Ethernet) MarshalBinary() ([]byte, error) {
	return e.encode(nil)
}

func (e *Ethernet) encode(b []byte) ([]byte, error) {
	b = append(b, e.Dst[:6]...)
	b = append(b, e.Src[:6]...)

	if e.VLan != 0 {
		b = append(b, 0x81, 0x00) // VLAN
		b = append(b, uint8(e.VLan>>8), uint8(e.VLan))
	}

	b = append(b, uint8(e.EtherType>>8), uint8(e.EtherType))

	return e.Inner.encode(b)
}
