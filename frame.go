package rawnet

// Frame represents a network protocol data unit at any layer.
// It's the core interface for all packet types in the rawnet library,
// providing methods for string representation and binary serialization.
type Frame interface {
	// String returns a human-readable representation of the frame
	String() string
	
	// MarshalBinary converts the frame to its binary representation
	MarshalBinary() ([]byte, error)
	
	// encode is an internal method that appends the frame's binary representation
	// to an existing byte slice, allowing for efficient concatenation of frames
	encode(b []byte) ([]byte, error)
}
