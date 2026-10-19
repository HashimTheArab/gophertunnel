package packet

import "fmt"

// SplitBatch splits an uncompressed, decrypted batch body into packets including their headers.
// The returned slices borrow data and cannot be appended into following packets. Malformed bodies
// return no packets. checkPacketLimit applies the decoder's client packet-count and empty-packet
// checks; server decoders normally disable those checks. The caller owns the total byte budget.
func SplitBatch(data []byte, checkPacketLimit bool) ([][]byte, error) {
	var packets [][]byte
	if err := walkBatch(data, checkPacketLimit, func(data []byte) error {
		packets = append(packets, data)
		return nil
	}); err != nil {
		return nil, err
	}
	return packets, nil
}

// AppendBatchPacket appends one packet, including its header, with its batch length prefix.
func AppendBatchPacket(body, data []byte) []byte {
	var length [5]byte
	body = append(body, length[:putVaruint32(&length, uint32(len(data)))]...)
	return append(body, data...)
}

// walkBatch validates framing and optionally visits each nonempty packet in order.
func walkBatch(data []byte, checkPacketLimit bool, f func([]byte) error) error {
	var packetCount int
	for len(data) != 0 {
		length, n, err := readPacketLength(data)
		if err != nil {
			return fmt.Errorf("decode batch: read packet length: %w", err)
		}
		data = data[n:]
		if length == 0 {
			if checkPacketLimit {
				return fmt.Errorf("decode batch: empty packet")
			}
			continue
		}
		if length > uint32(len(data)) {
			return fmt.Errorf("decode batch: packet length %v exceeds remaining %v", length, len(data))
		}
		if packetCount >= maximumInBatch && checkPacketLimit {
			return fmt.Errorf("decode batch: number of packets exceeds max=%v", maximumInBatch)
		}
		if f != nil {
			if err := f(data[:length:length]); err != nil {
				return err
			}
		}
		packetCount++
		data = data[length:]
	}
	return nil
}
