package main

import (
	"encoding/binary"
    "fmt"
	"strconv"
	"strings"
)

// TCP Flags
const (
	TCP_FIN = 1 << iota
	TCP_SYN
	TCP_RST
	TCP_PSH
	TCP_ACK
	TCP_URG
	TCP_ECE
	TCP_CWR
	TCP_NS
)

// Simple TCP packet parser
//
// Packet structure: http://en.wikipedia.org/wiki/Transmission_Control_Protocol
type TCPPacket struct {
	SrcPort    uint16
	DestPort   uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint16
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Payload    []byte
}

func ParseTCPPacket(b []byte) (p *TCPPacket) {
	t := &TCPPacket{
		SrcPort:    binary.BigEndian.Uint16(b[0:2]),
		DestPort:   binary.BigEndian.Uint16(b[2:4]),
		Seq:        binary.BigEndian.Uint32(b[4:8]),
		Ack:        binary.BigEndian.Uint32(b[8:12]),
		Flags:      binary.BigEndian.Uint16(b[12:14]) & 0x1FF,
		Window:     binary.BigEndian.Uint16(b[14:16]),
		Checksum:   binary.BigEndian.Uint16(b[16:18]),
		Urgent:     binary.BigEndian.Uint16(b[18:20]),
		DataOffset: (b[12] & 0xF0) >> 4,
	}

	t.Payload = make([]byte, len(b))
	copy(t.Payload, b[t.DataOffset*4:])

	return t
}

func (t *TCPPacket) String() string {
	return fmt.Sprintf("TCP %d > %d %s SEQ=%d ACK=%d",
		int(t.SrcPort), int(t.DestPort), t.FlagsString(),
		int64(t.Seq), int64(t.Ack))
}

func (t *TCPPacket) FlagsString() string {
	var sflags []string
	if 0 != (t.Flags & TCP_SYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (t.Flags & TCP_FIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (t.Flags & TCP_ACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (t.Flags & TCP_PSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (t.Flags & TCP_RST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (t.Flags & TCP_URG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (t.Flags & TCP_NS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (t.Flags & TCP_CWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (t.Flags & TCP_ECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, " "))
}

func (t *TCPPacket) Inspect() string {
	return strings.Join([]string{
		"Source port: " + strconv.Itoa(int(t.SrcPort)),
		"Dest port:" + strconv.Itoa(int(t.DestPort)),
		"Sequence:" + strconv.Itoa(int(t.Seq)),
		"Acknowledgment:" + strconv.Itoa(int(t.Ack)),
		"Header len:" + strconv.Itoa(int(t.DataOffset)),

		"Flag ns:" + strconv.FormatBool(t.Flags&TCP_NS != 0),
		"Flag crw:" + strconv.FormatBool(t.Flags&TCP_CWR != 0),
		"Flag ece:" + strconv.FormatBool(t.Flags&TCP_ECE != 0),
		"Flag urg:" + strconv.FormatBool(t.Flags&TCP_URG != 0),
		"Flag ack:" + strconv.FormatBool(t.Flags&TCP_ACK != 0),
		"Flag psh:" + strconv.FormatBool(t.Flags&TCP_PSH != 0),
		"Flag rst:" + strconv.FormatBool(t.Flags&TCP_RST != 0),
		"Flag syn:" + strconv.FormatBool(t.Flags&TCP_SYN != 0),
		"Flag fin:" + strconv.FormatBool(t.Flags&TCP_FIN != 0),

		"Window size:" + strconv.Itoa(int(t.Window)),
		"Checksum:" + strconv.Itoa(int(t.Checksum)),

		"Data:" + string(t.Payload),
	}, "\n")
}
