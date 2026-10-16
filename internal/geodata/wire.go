package geodata

import (
	"encoding/binary"
	"fmt"
)

// wireField refers to its original input buffer; DAT payloads are not copied.
type wireField struct {
	number uint64
	kind   uint64
	value  uint64
	bytes  []byte
}

func walk(data []byte, visit func(wireField) error) error {
	for len(data) > 0 {
		key, n := binary.Uvarint(data)
		if n <= 0 {
			return fmt.Errorf("truncated or overflowing protobuf field key")
		}
		data = data[n:]
		f := wireField{number: key >> 3, kind: key & 7}
		if f.number == 0 || f.number > (1<<29)-1 {
			return fmt.Errorf("invalid protobuf field number %d", f.number)
		}
		switch f.kind {
		case 0:
			f.value, n = binary.Uvarint(data)
			if n <= 0 {
				return fmt.Errorf("truncated or overflowing protobuf varint")
			}
			data = data[n:]
		case 1, 5:
			n = 8
			if f.kind == 5 {
				n = 4
			}
			if len(data) < n {
				return fmt.Errorf("truncated fixed-width protobuf value")
			}
			f.bytes, data = data[:n], data[n:]
		case 2:
			length, m := binary.Uvarint(data)
			if m <= 0 {
				return fmt.Errorf("truncated or overflowing protobuf length")
			}
			data = data[m:]
			if length > uint64(len(data)) {
				return fmt.Errorf("truncated protobuf payload")
			}
			n = int(length)
			f.bytes, data = data[:n], data[n:]
		default:
			return fmt.Errorf("unsupported protobuf wire type %d", f.kind)
		}
		if err := visit(f); err != nil {
			return err
		}
	}
	return nil
}

func expectWire(f wireField, kind uint64) error {
	if f.kind != kind {
		return fmt.Errorf("protobuf field %d: wire type %d, expected %d", f.number, f.kind, kind)
	}
	return nil
}
