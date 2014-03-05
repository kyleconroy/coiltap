package main

import (
	"encoding/binary"
	"fmt"
)

// Probably should go in different file
type LinkHeader struct {
	Type   int // protocol type, see LINKTYPE_*
	DstMac uint64
	SrcMac uint64
}

func (lp *LinkHeader) String() string {
	return fmt.Sprintf("srcmac: %d destmac:%d", lp.SrcMac, lp.DstMac)
}

func (lp *LinkHeader) Payload(b []byte) []byte {
	return b[14:]
}

func decodemac(pkt []byte) uint64 {
	mac := uint64(0)
	for i := uint(0); i < 6; i++ {
		mac = (mac << 8) + uint64(pkt[i])
	}
	return mac
}

func ParseLinkHeader(b []byte) (*LinkHeader, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("need at least 24 bytes for a valid ethernet frame")
	}
	lp := &LinkHeader{
		Type:   int(binary.BigEndian.Uint16(b[12:14])),
		DstMac: decodemac(b[0:6]),
		SrcMac: decodemac(b[6:12]),
	}
	return lp, nil
}
