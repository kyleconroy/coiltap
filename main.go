package main

import (
        "io/ioutil"
	"bufio"
	"bytes"
	"code.google.com/p/go.net/ipv4"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type PacketAddr struct {
	pkt *TCPPacket
	hdr *ipv4.Header
}

var verbose bool

// Returns the string representation of a packet tuple
func tcptuple(src net.IP, srcPort uint16, dst net.IP, dstPort uint16) string {
	return fmt.Sprintf("%s:%d>%s:%d", src, int(srcPort), dst, int(dstPort))
}

func parseRequest(packets chan *PacketAddr) *http.Request {
	var b bytes.Buffer

	for {
		pktaddr := <-packets
		pkt := pktaddr.pkt
		// This shouldn't happen, but just in case it does
		if len(pkt.Payload) == 0 {
			continue
		}

		if verbose {
			log.Printf("Processing request: %s ", pkt)
		}

		n := bytes.Index(pkt.Payload, []byte{0})
		b.Write(pkt.Payload[:n])

		request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(b.Bytes())))

		if err != nil {
			log.Println("Error parsing request")
			continue
		}

		return request
	}
}

func parseResponse(packets chan *PacketAddr, req *http.Request) *http.Response {
	var b bytes.Buffer

	for {
		pktaddr := <-packets
		pkt := pktaddr.pkt

		// This shouldn't happen, but just in case it does
		if len(pkt.Payload) == 0 {
			continue
		}

		if verbose {
			log.Printf("Processing response: %s ", pkt)
		}

		n := bytes.Index(pkt.Payload, []byte{0})
		b.Write(pkt.Payload[:n])

		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b.Bytes())), req)

		if err != nil {
            log.Println("Error parsing response:", err)
			continue
		}

        _, err = ioutil.ReadAll(response.Body)

		if err != nil {
            log.Println("Error parsing response body:", err)
			continue
		}

		return response
	}
}

func processStream(packets chan *PacketAddr, sink Sink, port int) {
	for {
		request := parseRequest(packets)
		response := parseResponse(packets, request)
		sink.Put(request, response, time.Second)
	}
}

// Capture packets on the given device using libpcap. Only packets sent to or
// from the given port are captured. The packets are reassembled back into the
// HTTP traffic.
func sniff(packets chan *PacketAddr, device net.Interface, port int, sink Sink) {
	// Memory leak
	// We need a way to clean up closed channels
	streams := map[string]chan *PacketAddr{}
	uport := uint16(port)

	for {
		var key string
		pktaddr := <-packets
		pkt := pktaddr.pkt
		hdr := pktaddr.hdr

		if pkt.SrcPort == uport {
			key = tcptuple(hdr.Src, pkt.SrcPort, hdr.Dst, pkt.DstPort)
		} else {
			key = tcptuple(hdr.Dst, pkt.DstPort, hdr.Src, pkt.SrcPort)
		}

		stream, found := streams[key]

		// If the packet if from the server and we haven't created a stream yet,
		// this means that the connection started before capture, so we just throw
		// this on the ground.
		if !found && pkt.SrcPort == uport {
			log.Println("Packet was from the server, so we already missed the request")
			continue
		}

		if !found {
			stream = make(chan *PacketAddr, 10)
			streams[key] = stream
			go processStream(stream, sink, port)
		}

		stream <- pktaddr
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

			// Only ship off packets with payloads
			if len(p.Payload) == 0 {
				continue
			}

            // Null bytes are coming from somewhere
            // If the first byte is null, ignore
		    nn := bytes.Index(p.Payload, []byte{0})
            if nn == 0 {
                    continue
                }

			pa := PacketAddr{pkt: p, hdr: hdr}
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
