package rawnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type ICMP struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Body     uint32

	Payload []byte
}

func ParseICMP(data []byte) (Frame, error) {
	if len(data) < 8 {
		return InvalidFrame(data), errors.New("ICMP packet not at least 8 bytes long")
	}
	buf := bytes.NewReader(data)
	res := new(ICMP)

	binary.Read(buf, binary.BigEndian, &res.Type)
	binary.Read(buf, binary.BigEndian, &res.Code)
	binary.Read(buf, binary.BigEndian, &res.Checksum)
	binary.Read(buf, binary.BigEndian, &res.Body)

	res.Payload = data[8:]

	return res, nil
}

func (f *ICMP) String() string {
	return fmt.Sprintf("ICMP(%s)", f.Message())
}

func (f *ICMP) Message() string {
	switch f.Type {
	case 0:
		return "Echo reply"
	case 3:
		return fmt.Sprintf("Destination Unreachable (%d)", f.Code)
	case 5:
		return fmt.Sprintf("Redirect Message (%d)", f.Code)
	case 8:
		return "Echo Request"
	}
	return fmt.Sprintf("%d/%d", f.Type, f.Code)
}

func (f *ICMP) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *ICMP) encode(b []byte) ([]byte, error) {
	tmpBuf := make([]byte, 4)

	pos := len(b)

	b = append(b, f.Type, f.Code, 0, 0)
	binary.BigEndian.PutUint32(tmpBuf, f.Body)
	b = append(b, tmpBuf...)

	b = append(b, f.Payload...)

	// Checksum specified in RFC 1071

	// TODO: checksum
	s := netChecksum(b[pos:])
	b[pos+2] ^= byte(s)
	b[pos+3] ^= byte(s >> 8)

	return b, nil
}
