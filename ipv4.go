package rawnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type IPv4 struct {
	Version  uint8
	Len      uint8 // 4=20bytes
	TOS      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint16
	FragOff  uint16 // max 0x1fff
	TTL      uint8
	Protocol L4Proto
	Checksum uint16
	Src      net.IP
	Dst      net.IP
	Options  []byte

	Inner Frame
}

func ParseIPv4(data []byte) (*IPv4, error) {
	res := new(IPv4)
	var err error

	if len(data) < 20 {
		return nil, errors.New("not enough data to parse ipv4")
	}

	res.Version = data[0] >> 4
	res.Len = data[0] & 0xf
	res.TOS = data[1]
	res.TotalLen = binary.BigEndian.Uint16(data[2:4])
	res.ID = binary.BigEndian.Uint16(data[4:6])
	res.Flags = binary.BigEndian.Uint16(data[6:8])
	res.FragOff = res.Flags & 0x1fff
	res.Flags = res.Flags >> 13
	res.TTL = data[8]
	res.Protocol = L4Proto(data[9])
	res.Checksum = binary.BigEndian.Uint16(data[10:12])

	hlen := res.Len << 2
	if len(data) < int(hlen) {
		return nil, errors.New("not enough data to parse ipv4")
	}

	res.Src = net.IP(data[12:16])
	res.Dst = net.IP(data[16:20])

	if hlen > 20 {
		res.Options = data[20:hlen]
	} else {
		res.Options = nil
	}

	data = data[hlen:]

	res.Inner, err = ParseLayer4(L4Proto(res.Protocol), data)
	return res, err
}

func (i *IPv4) String() string {
	return fmt.Sprintf("IPv4(%v->%v)[%v]", i.Src, i.Dst, i.Inner)
}

func (i *IPv4) MarshalBinary() ([]byte, error) {
	return i.encode(nil)
}

func (i *IPv4) encode(b []byte) ([]byte, error) {
	tmpBuf := make([]byte, 2)

	pos := len(b)
	hdrlen := uint8(len(i.Options) + 20)
	b = append(b, 4<<4|(hdrlen>>2&0x0f), i.TOS, 0, 0) // total length=0 (for now)

	binary.BigEndian.PutUint16(tmpBuf, i.ID)
	b = append(b, tmpBuf...)

	flagsAndFragOff := (i.FragOff & 0x1fff) | (i.Flags << 13)
	binary.BigEndian.PutUint16(tmpBuf, flagsAndFragOff)
	b = append(b, tmpBuf...)

	b = append(b, i.TTL, uint8(i.Protocol), 0, 0) // checksum=0 (for now)

	if ip := i.Src.To4(); ip != nil {
		b = append(b, ip...)
	} else {
		return nil, errors.New("ipv4: invalid src ip")
	}
	if ip := i.Dst.To4(); ip != nil {
		b = append(b, ip...)
	} else {
		return nil, errors.New("ipv4: invalid dst ip")
	}

	endIP := len(b)

	b = append(b, i.Options...)

	b, err := i.Inner.encode(b)
	if err != nil {
		return nil, err
	}

	// update total len
	totalLen := uint16(len(b) - pos)
	binary.BigEndian.PutUint16(b[pos+2:pos+4], totalLen)

	// update checksum

	s := netChecksum(b[pos:endIP])
	b[pos+10] ^= byte(s)
	b[pos+11] ^= byte(s >> 8)

	return b, nil
}

func (i *IPv4) GetInner() Frame {
	return i.Inner
}
