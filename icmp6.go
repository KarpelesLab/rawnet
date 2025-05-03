package rawnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type ICMP6 struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Body     uint32

	Payload []byte
}

func ParseICMP6(data []byte) (Frame, error) {
	if len(data) < 8 {
		return InvalidFrame(data), errors.New("invalid ICMP6 frame, too short")
	}

	buf := bytes.NewReader(data)
	res := new(ICMP6)

	binary.Read(buf, binary.BigEndian, &res.Type)
	binary.Read(buf, binary.BigEndian, &res.Code)
	binary.Read(buf, binary.BigEndian, &res.Checksum)
	binary.Read(buf, binary.BigEndian, &res.Body)

	res.Payload = data[8:]

	return res, nil
}

func (f *ICMP6) String() string {
	return "ICMP6[" + f.Message() + "]"
}

func (f *ICMP6) Message() string {
	switch f.Type {
	case 1:
		switch f.Code {
		case 0:
			return "Destination unreachable: No route to destination"
		case 1:
			return "Destination unreachable: communication with destination administratively prohibited"
		case 2:
			return "Destination unreachable: beyond scope of source address"
		}
		return fmt.Sprintf("Destination unreachable: (%d)", f.Code)
	case 2:
		return "Packet too big"
	case 128:
		return "Echo Request"
	case 129:
		return "Echo Reply"
	case 133:
		return "Router Solicitation (NDP)"
	}

	return fmt.Sprintf("(%d/%d)", f.Type, f.Code)
}

func (f *ICMP6) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *ICMP6) encode(b []byte) ([]byte, error) {
	pos := len(b)
	b = append(b, f.Type, f.Code, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(b[pos+4:], f.Body)

	b = append(b, f.Payload...)

	// TODO checksum

	return b, nil
}
