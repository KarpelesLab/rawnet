package rawnet

import "fmt"

type InvalidFrame []byte

func (i InvalidFrame) String() string {
	return fmt.Sprintf("InvalidFrame[%d bytes]", len(i))
}

func (i InvalidFrame) MarshalBinary() ([]byte, error) {
	return i, nil
}

func (i InvalidFrame) encode(b []byte) ([]byte, error) {
	return append(b, i...), nil
}
