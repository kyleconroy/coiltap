package main

import (
        "strconv"
	"bufio"
	"bytes"
	"code.google.com/p/go.net/ipv4"
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
	pkt *TCPPacket
	hdr *ipv4.Header
}

var verbose bool

// Returns the string representation of a packet tuple
func TCPTuple(t *TCPPacket, hdr *ipv4.Header) string {
	return fmt.Sprintf("%s:%d>%s:%d", hdr.Src, int(t.SrcPort), hdr.Dst, int(t.DstPort))
}

func process(hdr *ipv4.Header, t *TCPPacket, sink Sink, port int,
	bodies map[string]string, times map[string]time.Time) error {
	tuple := TCPTuple(t, hdr)
	if tuple == "" {
		return fmt.Errorf("No TCP tuple")
	}
	if len(t.Payload) > 0 {
		n := bytes.Index(t.Payload, []byte{0})
		bodies[tuple] += string(t.Payload[:n])
	}
	if t.DstPort == uint16(port) && (t.Flags&TCP_SYN) != 0 {
		times[tuple] = time.Now()
	}
	// It's all over
	if t.DstPort == uint16(port) && (t.Flags&TCP_FIN != 0 || t.Flags&TCP_RST != 0) {
		var requestID, responseID string

		reversePacket := &TCPPacket{SrcPort: t.DstPort, DstPort: t.SrcPort}
		reverseHeader := &ipv4.Header{Src: hdr.Dst, Dst: hdr.Src}

		requestID = tuple
		responseID = TCPTuple(reversePacket, reverseHeader)

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
	times := map[string]time.Time{}
	bodies := map[string]string{}

	for {
		pktaddr := <-packets
		err := process(pktaddr.hdr, pktaddr.pkt, sink, port, bodies, times)
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
	snaplen := 65535
	conn, err := OpenLive(iface.Name, int32(snaplen), true, 100)

	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	err = conn.SetFilter("tcp port " + strconv.Itoa(port))

	log.Printf("Listening to HTTP traffic on port %d on interface %s", port, iface.Name)

	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, snaplen)

	for {
		// Note: ReadFrom receive messages without IP header
		n, _, err := conn.ReadFrom(buf)

		if err != nil {
			log.Println("Error:", err)
			continue
		}

		if n > 0 {
			hdr, p, err := parsePacket(buf[:n])

			if err != nil {
				log.Println("Error:", err)
				continue
			}
			pa := PacketAddr{pkt: p, hdr: hdr}
            log.Println(hdr)
            log.Println(p)
			packets <- &pa
		}
	}
}

func IPPayload(h *ipv4.Header, b []byte) []byte {
	end := h.TotalLen
	if h.TotalLen > len(b) {
		end = len(b)
	}
	return b[h.Len:end]
}

func parsePacket(buf []byte) (*ipv4.Header, *TCPPacket, error) {
	lh, err := ParseLinkHeader(buf)
	if err != nil {
		return nil, nil, err
	}
	// We're assuming this is an IP packet
	ipPacket := lh.Payload(buf)
	hdr, err := ipv4.ParseHeader(ipPacket)
	if err != nil {
		return nil, nil, err
	}
	p, err := ParseTCPPacket(IPPayload(hdr, ipPacket))
	if err != nil {
		return nil, nil, err
	}
	return hdr, p, nil
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
