package rawnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type IPv6 struct {
	Version    uint8
	Class      uint8
	FlowLabel  uint32 // actually 20 bytes
	PayloadLen uint16
	NextHeader L4Proto
	HopLimit   uint8 // TTL
	Src        net.IP
	Dst        net.IP

	Inner Frame
}

func ParseIPv6(data []byte) (*IPv6, error) {
	res := new(IPv6)
	var err error

	if len(data) < 40 {
		return nil, errors.New("not enough data to parse ipv6")
	}

	res.Version = data[0] >> 4
	res.Class = (data[0]<<4 | data[1]>>4)
	res.FlowLabel = uint32(data[1]&0xf)<<16 | uint32(data[2])<<8 | uint32(data[3])
	res.PayloadLen = binary.BigEndian.Uint16(data[4:6])
	res.NextHeader = L4Proto(data[6])
	res.HopLimit = data[7]

	res.Src = net.IP(data[8:24])
	res.Dst = net.IP(data[24:40])

	res.Inner, err = ParseLayer4(L4Proto(res.NextHeader), data[40:])
	return res, err
}

func (i *IPv6) String() string {
	return fmt.Sprintf("IPv6(%v->%v)[%v]", i.Src, i.Dst, i.Inner)
}

func (i *IPv6) MarshalBinary() ([]byte, error) {
	return i.encode(nil)
}

func (i *IPv6) encode(b []byte) ([]byte, error) {
	b = append(b,
		i.Version<<4|i.Class>>4,
		i.Class<<4|(byte(i.FlowLabel>>16)&0xf),
		byte(i.FlowLabel>>8),
		byte(i.FlowLabel),

		0, 0, // Payload Len (to be defined)
		byte(i.NextHeader),
		i.HopLimit,
	)

	b = append(b, i.Src.To16()...)
	b = append(b, i.Dst.To16()...)

	b, err := i.Inner.encode(b)
	if err != nil {
		return nil, err
	}

	// update length
	binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))

	return b, nil
}

func (i *IPv6) GetInner() Frame {
	return i.Inner
}
