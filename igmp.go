package rawnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type IGMP struct {
	Type        uint8
	MaxRespTime uint8
	Checksum    uint16
	GroupAddr   uint32

	Payload []byte
}

func ParseIGMP(data []byte) (Frame, error) {
	if len(data) < 8 {
		return InvalidFrame(data), fmt.Errorf("not enough data to parse IGMP (only %d bytes)", len(data))
	}

	buf := bytes.NewReader(data)
	res := new(IGMP)

	binary.Read(buf, binary.BigEndian, &res.Type)
	binary.Read(buf, binary.BigEndian, &res.MaxRespTime)
	binary.Read(buf, binary.BigEndian, &res.Checksum)
	binary.Read(buf, binary.BigEndian, &res.GroupAddr)

	if len(data) > 8 {
		res.Payload = data[8:]
	}

	return res, nil
}

func (f *IGMP) String() string {
	return fmt.Sprintf("IGMP(%v)", f.Type)
}

func (f *IGMP) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *IGMP) encode(b []byte) ([]byte, error) {
	pos := len(b)
	b = append(b, f.Type, f.MaxRespTime, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(b[pos+4:], f.GroupAddr)

	b = append(b, f.Payload...)

	return b, nil
}
