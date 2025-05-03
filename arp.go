package rawnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

type ARP struct {
	HType      uint16
	PType      Protocol
	HLen, PLen uint8
	Oper       uint16

	SenderHW   net.HardwareAddr
	SenderAddr net.IP

	TargetHW   net.HardwareAddr
	TargetAddr net.IP
}

func ParseARP(data []byte) (Frame, error) {
	if len(data) < 26 {
		return InvalidFrame(data), errors.New("ARP packet not at least 26 bytes long")
	}
	buf := bytes.NewReader(data)
	res := new(ARP)

	binary.Read(buf, binary.BigEndian, &res.HType)
	binary.Read(buf, binary.BigEndian, &res.PType)
	binary.Read(buf, binary.BigEndian, &res.HLen)
	binary.Read(buf, binary.BigEndian, &res.PLen)
	binary.Read(buf, binary.BigEndian, &res.Oper)

	sha := make([]byte, res.HLen)
	spa := make([]byte, res.PLen)
	tha := make([]byte, res.HLen)
	tpa := make([]byte, res.PLen)

	_, err := io.ReadFull(buf, sha)
	if err != nil {
		return InvalidFrame(data), err
	}
	_, err = io.ReadFull(buf, spa)
	if err != nil {
		return InvalidFrame(data), err
	}
	_, err = io.ReadFull(buf, tha)
	if err != nil {
		return InvalidFrame(data), err
	}
	_, err = io.ReadFull(buf, tpa)
	if err != nil {
		return InvalidFrame(data), err
	}

	res.SenderHW = net.HardwareAddr(sha)
	res.SenderAddr = net.IP(spa)
	res.TargetHW = net.HardwareAddr(tha)
	res.TargetAddr = net.IP(tpa)

	return res, nil
}

func (f *ARP) Swap() {
	f.SenderHW, f.TargetHW = f.TargetHW, f.SenderHW
	f.SenderAddr, f.TargetAddr = f.TargetAddr, f.SenderAddr
}

func (f *ARP) String() string {
	t := "Request"
	if f.Oper == 2 {
		t = "Response"
	}
	return fmt.Sprintf("ARP(%s %04x %s %v=>%v %v=>%v)", t, f.HType, f.PType, f.SenderHW, f.TargetHW, f.SenderAddr, f.TargetAddr)
}

func (f *ARP) MarshalBinary() ([]byte, error) {
	return f.encode(nil)
}

func (f *ARP) encode(b []byte) ([]byte, error) {
	tmpBuf := make([]byte, 2)

	binary.BigEndian.PutUint16(tmpBuf, f.HType)
	b = append(b, tmpBuf...)
	binary.BigEndian.PutUint16(tmpBuf, uint16(f.PType))
	b = append(b, tmpBuf...)

	b = append(b, f.HLen, f.PLen)

	binary.BigEndian.PutUint16(tmpBuf, f.Oper)
	b = append(b, tmpBuf...)

	b = append(b, f.SenderHW...)
	b = append(b, f.SenderAddr...)
	b = append(b, f.TargetHW...)
	b = append(b, f.TargetAddr...)

	return b, nil
}
