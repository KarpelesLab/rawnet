package rawnet

type Frame interface {
	String() string
	MarshalBinary() ([]byte, error)
	encode(b []byte) ([]byte, error)
}
