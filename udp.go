package rawnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16

	Payload []byte
}

func ParseUDP(data []byte) (Frame, error) {
	buf := bytes.NewReader(data)
	res := new(UDP)

	binary.Read(buf, binary.BigEndian, &res.SrcPort)
	binary.Read(buf, binary.BigEndian, &res.DstPort)
	binary.Read(buf, binary.BigEndian, &res.Length)
	binary.Read(buf, binary.BigEndian, &res.Checksum)

	res.Payload = data[8:]

	return res, nil
}

func MakeUDPIP(src, dst net.IP, srcPort, dstPort uint16, data []byte) (Frame, error) {
	var out Frame

	out = &UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Payload: data,
	}

	if src4 := src.To4(); src4 != nil {
		dst4 := dst.To4()

		// ipv4
		out = &IPv4{
			TTL:      64, // sensible default, as used on Linux among others
			Protocol: L4UDP,
			Src:      src4,
			Dst:      dst4,
			Inner:    out,
		}

		return out, nil
	}

	return nil, fmt.Errorf("ipv6 not supported yet")
}

func (f *UDP) String() string {
	return fmt.Sprintf("UDP(%v->%v)[%d bytes]", f.SrcPort, f.DstPort, len(f.Payload))
}

func (f *UDP) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *UDP) encode(b []byte) ([]byte, error) {
	if len(f.Payload) > 0xffff {
		return nil, fmt.Errorf("payload length too long for udp")
	}
	tmpBuf := []byte{0, 0}

	binary.BigEndian.PutUint16(tmpBuf, f.SrcPort)
	b = append(b, tmpBuf...)
	binary.BigEndian.PutUint16(tmpBuf, f.DstPort)
	b = append(b, tmpBuf...)
	binary.BigEndian.PutUint16(tmpBuf, uint16(len(f.Payload)))
	b = append(b, tmpBuf...)
	b = append(b, 0, 0) // checksum

	b = append(b, f.Payload...)

	// TODO checksum

	return b, nil
}
