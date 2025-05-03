package rawnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type TCP struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Flags      uint16
	WindowSize uint16
	Checksum   uint16
	UrgentPtr  uint16

	Options []byte
	Payload []byte
}

func ParseTCP(data []byte) (Frame, error) {
	if len(data) < 20 {
		return InvalidFrame(data), errors.New("invalid TCP frame")
	}

	buf := bytes.NewReader(data)
	res := new(TCP)

	binary.Read(buf, binary.BigEndian, &res.SrcPort)
	binary.Read(buf, binary.BigEndian, &res.DstPort)
	binary.Read(buf, binary.BigEndian, &res.Seq)
	binary.Read(buf, binary.BigEndian, &res.Ack)
	binary.Read(buf, binary.BigEndian, &res.Flags)
	binary.Read(buf, binary.BigEndian, &res.WindowSize)
	binary.Read(buf, binary.BigEndian, &res.Checksum)
	binary.Read(buf, binary.BigEndian, &res.UrgentPtr)

	// header size
	headerSize := int(res.Flags>>12&0xf) * 4

	if len(data) < headerSize {
		return InvalidFrame(data), errors.New("invalid TCP frame")
	}

	res.Options = data[20:headerSize]
	res.Payload = data[headerSize:]

	return res, nil
}

func (f *TCP) String() string {
	return fmt.Sprintf("TCP(%v->%v)[%d bytes]", f.SrcPort, f.DstPort, len(f.Payload))
}

func (f *TCP) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *TCP) encode(b []byte) ([]byte, error) {
	pos := len(b)

	if cap(b) >= pos+20 {
		b = b[:pos+20]
	} else {
		buf := make([]byte, pos+20, pos+1500)
		copy(buf, b)
		b = buf
	}

	hdrPos := b[pos:]
	binary.BigEndian.PutUint16(hdrPos[:2], f.SrcPort)
	binary.BigEndian.PutUint16(hdrPos[2:4], f.DstPort)
	binary.BigEndian.PutUint32(hdrPos[4:8], f.Seq)
	binary.BigEndian.PutUint32(hdrPos[8:12], f.Ack)
	binary.BigEndian.PutUint16(hdrPos[12:14], f.Flags)
	binary.BigEndian.PutUint16(hdrPos[14:16], f.WindowSize)
	binary.BigEndian.PutUint16(hdrPos[16:18], uint16(0)) // checksum
	binary.BigEndian.PutUint16(hdrPos[18:20], f.UrgentPtr)

	b = append(b, f.Options...)
	b = append(b, f.Payload...)

	return b, nil
}
