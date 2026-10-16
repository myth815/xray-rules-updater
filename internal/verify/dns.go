package verify

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

func ready(ctx context.Context, p *process, address string) error {
	until := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-p.done:
			return failure("verify_mosdns_exit")
		case <-ctx.Done():
			return failure("verify_timeout")
		default:
		}
		if e := queryTimeout(ctx, address, "invalid::probe.invalid", 3, false, 150*time.Millisecond); e == nil {
			return nil
		}
		if time.Now().After(until) {
			return failure("verify_mosdns_ready")
		}
		t := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return failure("verify_timeout")
		case <-p.done:
			t.Stop()
			return failure("verify_mosdns_exit")
		case <-t.C:
		}
	}
}
func query(ctx context.Context, address, name string, rcode int, wantA bool) error {
	return queryTimeout(ctx, address, name, rcode, wantA, 15*time.Second)
}
func queryTimeout(ctx context.Context, address, name string, rcode int, wantA bool, timeout time.Duration) error {
	packet := make([]byte, 12)
	if _, e := rand.Read(packet[:2]); e != nil {
		return e
	}
	packet[2] = 1
	packet[5] = 1
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("invalid query name")
		}
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	connection, e := (&net.Dialer{}).DialContext(ctx, "udp", address)
	if e != nil {
		return e
	}
	defer connection.Close()
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if _, e = connection.Write(packet); e != nil {
		return e
	}
	reply := make([]byte, 65535)
	n, e := connection.Read(reply)
	if e != nil {
		return e
	}
	return checkReply(reply[:n], binary.BigEndian.Uint16(packet[:2]), rcode, wantA)
}
func skipName(packet []byte, offset int) (int, error) {
	for count := 0; count < 128; count++ {
		if offset >= len(packet) {
			return 0, errors.New("truncated name")
		}
		n := int(packet[offset])
		offset++
		if n == 0 {
			return offset, nil
		}
		if n&0xc0 == 0xc0 {
			if offset >= len(packet) {
				return 0, errors.New("truncated pointer")
			}
			pointer := ((n & 0x3f) << 8) | int(packet[offset])
			if pointer >= len(packet) {
				return 0, errors.New("invalid pointer")
			}
			return offset + 1, nil
		}
		if n > 63 || offset+n > len(packet) {
			return 0, errors.New("invalid name")
		}
		offset += n
	}
	return 0, errors.New("name too long")
}
func checkReply(packet []byte, id uint16, rcode int, wantA bool) error {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[:2]) != id || packet[2]&0x80 == 0 || packet[2]&2 != 0 || int(packet[3]&15) != rcode {
		return errors.New("invalid DNS response")
	}
	offset := 12
	for range int(binary.BigEndian.Uint16(packet[4:6])) {
		var e error
		offset, e = skipName(packet, offset)
		if e != nil || offset+4 > len(packet) {
			return errors.New("invalid question")
		}
		offset += 4
	}
	found := false
	for range int(binary.BigEndian.Uint16(packet[6:8])) {
		var e error
		offset, e = skipName(packet, offset)
		if e != nil || offset+10 > len(packet) {
			return errors.New("invalid answer")
		}
		kind := binary.BigEndian.Uint16(packet[offset : offset+2])
		class := binary.BigEndian.Uint16(packet[offset+2 : offset+4])
		length := int(binary.BigEndian.Uint16(packet[offset+8 : offset+10]))
		offset += 10
		if offset+length > len(packet) {
			return errors.New("truncated answer")
		}
		if kind == 1 && class == 1 && length == 4 {
			found = true
		}
		offset += length
	}
	if wantA && !found {
		return errors.New("no A answer")
	}
	return nil
}
