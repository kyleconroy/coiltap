package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type PacketAddr struct {
	pkt  *TCPPacket
	addr net.Addr
}

var verbose bool

// Returns the string representation of a packet tuple
func TCPTuple(t *TCPPacket, src net.Addr, dest net.Addr) string {
	srcAddr := strings.Split(src.String(), "/")
	destAddr := strings.Split(dest.String(), "/")
	return fmt.Sprintf("%s:%d>%s:%d", srcAddr[0], int(t.SrcPort), destAddr[0], int(t.DestPort))
}

func process(t *TCPPacket, src net.Addr, dest net.Addr, sink Sink, port int, bodies map[string]string,
	times map[string]time.Time) error {
	tuple := TCPTuple(t, src, dest)
	if tuple == "" {
		return fmt.Errorf("No TCP tuple")
	}
	if len(t.Payload) > 0 {
		n := bytes.Index(t.Payload, []byte{0})
		bodies[tuple] += string(t.Payload[:n])
	}
	if t.DestPort == uint16(port) && (t.Flags&TCP_SYN) != 0 {
		times[tuple] = time.Now()
	}
	// It's all over
	if t.DestPort == uint16(port) && (t.Flags&TCP_FIN != 0 || t.Flags&TCP_RST != 0) {
		var requestID, responseID string

		requestID = tuple
		responseID = TCPTuple(&TCPPacket{SrcPort: t.DestPort, DestPort: t.SrcPort}, dest, src)

		defer func() {
			delete(times, requestID)
			delete(times, responseID)
			delete(bodies, requestID)
			delete(bodies, responseID)
		}()

		requestPayload, qok := bodies[requestID]
		responsePayload, sok := bodies[responseID]
		if !sok {
			return fmt.Errorf("No response payload for %s", responseID)
		}
		if !qok {
			return fmt.Errorf("No request payload for %s", requestID)
		}

		requestBuf := bufio.NewReader(strings.NewReader(requestPayload))
		responseBuf := bufio.NewReader(strings.NewReader(responsePayload))

		request, err := http.ReadRequest(requestBuf)
		if err != nil {
			return fmt.Errorf("Request creation failed for %s: %s", requestID, err)
		}
		response, err := http.ReadResponse(responseBuf, request)
		if err != nil {
			return fmt.Errorf("Response creation failed for %s: %s", responseID, err)
		}

		sink.Put(request, response, time.Second)
	}
	return nil
}

// Capture packets on the given device using libpcap. Only packets sent to or
// from the given port are captured. The packets are reassembled back into the
// HTTP traffic.
//
func sniff(packets chan *PacketAddr, device net.Interface, port int, sink Sink) {
	addrs, err := device.Addrs()

	if err != nil {
		log.Fatal(err)
	}

	times := map[string]time.Time{}
	bodies := map[string]string{}

	log.Printf("Listening to HTTP traffic on port %d on interface %s", port, device.Name)

	for {
		pktaddr := <-packets
		err := process(pktaddr.pkt, pktaddr.addr, addrs[0],
			sink, port, bodies, times)
		if verbose {
			if err != nil {
				log.Printf("FAIL %+v: %s", pktaddr.pkt, err)
			} else {
				log.Printf("OKAY %+v", pktaddr.pkt)
			}
		}
	}
}

// A port is really just a fancy word for BPF filters
func listen(packets chan *PacketAddr, iface net.Interface, port int) {
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	parts := strings.Split(addrs[0].String(), "/")
	conn, err := net.ListenPacket("ip4:tcp", parts[0])

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	buf := make([]byte, 65535)

	for {
		// Note: ReadFrom receive messages without IP header
		n, a, err := conn.ReadFrom(buf)

		if err != nil {
			log.Println("Error:", err)
			continue
		}

		if n > 0 {
			src := int(binary.BigEndian.Uint16(buf[0:2]))
			dest := int(binary.BigEndian.Uint16(buf[2:4]))

			if src == port || dest == port {
				p := ParseTCPPacket(buf[:n])
				pa := PacketAddr{pkt: p, addr: a}
				packets <- &pa
			}
		}
	}
}

func capturePackets() {
	snaplen := 65535
	conn, _ := OpenLive("eth0", int32(snaplen), true, 100)

    conn.SetFilter("port 3000")

	buf := make([]byte, snaplen)

	for {
		n, hdr, _ := conn.ReadFrom(buf)
        if n > 0 {
			src := int(binary.BigEndian.Uint16(buf[0:2]))
			dest := int(binary.BigEndian.Uint16(buf[2:4]))
            log.Printf("%d %+v src:%d dest:%d", n, hdr, src, dest)
        }
	}
}

func main() {
	var device, esurl string
	var port int

	flag.StringVar(&device, "i", "", "interface")
	flag.StringVar(&esurl, "e", "http://localhost:9200/coiltap", "elastic-url")
	flag.IntVar(&port, "p", 80, "port")
	flag.BoolVar(&verbose, "v", false, "verbose")

	flag.Usage = func() {
		log.Fatalf("usage: %s [ -i interface ] [ -p port ] [-e elastic-url]", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	capturePackets()

	ifaces := []net.Interface{}
	var err error

	if device == "" {
		ifaces, err = net.Interfaces()
		if err != nil || len(ifaces) == 0 {
			log.Fatalf("Couldn't find any devices: %s", err)
		}
	} else {
		iface, err := net.InterfaceByName(device)
		if err != nil {
			log.Fatalf("Couldn't find that interface %s: %s", device, err)
		}
		ifaces = append(ifaces, *iface)
	}

	sink, err := NewSink(esurl)

	if err != nil {
		log.Fatal(err)
	}

	sink.Run()

	for _, iface := range ifaces {
		packetchan := make(chan *PacketAddr, 1000)

		if err != nil {
			log.Fatal(err)
		}

		go listen(packetchan, iface, port)
		go sniff(packetchan, iface, port, sink)
	}

	select {
	case <-make(chan bool):
	}
}
