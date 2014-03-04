package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var verbose bool

func NewHandle(device string, port int, snaplen int) (*Pcap, error) {
	handle, err := OpenLive(device, int32(snaplen), true, 1000)

	if handle == nil || err != nil {
		return nil, fmt.Errorf("Couldn't Open live connection to interface: %s", err)
	}

	err = handle.SetFilter("port " + strconv.Itoa(port))

	if err != nil {
		return nil, fmt.Errorf("Failed to add filter to handle: %s", err)
	}

	return handle, nil
}

// Returns the string representation of a packet tuple
func tcpTuple(p *Packet) string {
	if len(p.Headers) == 2 {
		if hdr, ok := p.Headers[0].(addrHdr); ok {
			return fmt.Sprintf("%s:%d>%s:%d", hdr.SrcAddr(), int(p.TCP.SrcPort),
				hdr.DestAddr(), int(p.TCP.DestPort))
		}
	}
	return ""
}

func tcpReverseTuple(p *Packet) string {
	if len(p.Headers) == 2 {
		if hdr, ok := p.Headers[0].(addrHdr); ok {
			return fmt.Sprintf("%s:%d>%s:%d", hdr.DestAddr(), int(p.TCP.DestPort),
				hdr.SrcAddr(), int(p.TCP.SrcPort))
		}
	}
	return ""
}

func process(pkt *Packet, sink Sink, port int, bodies map[string]string, times map[string]time.Time) error {
	if pkt.TCP == nil {
		return fmt.Errorf("No TCP header")
	}
	tuple := tcpTuple(pkt)
	if tuple == "" {
		return fmt.Errorf("No TCP tuple")
	}
	if len(pkt.Payload) > 0 {
		bodies[tuple] += string(pkt.Payload)
	}
	if pkt.TCP.DestPort == uint16(port) && (pkt.TCP.Flags&TCP_SYN) != 0 {
		times[tuple] = time.Now()
	}
	// It's all over
	if pkt.TCP.DestPort == uint16(port) && (pkt.TCP.Flags&TCP_FIN != 0 || pkt.TCP.Flags&TCP_RST != 0) {
		var requestID, responseID string

		requestID = tuple
		responseID = tcpReverseTuple(pkt)

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
func sniff(handle *Pcap, sink Sink, port int, dev string) {
	defer handle.Close()

	times := map[string]time.Time{}
	bodies := map[string]string{}

	log.Printf("Listening to HTTP traffic on port %d on interface %s", port, dev)

	for {
		for pkt := handle.Next(); pkt != nil; pkt = handle.Next() {
			pkt.Decode()

			err := process(pkt, sink, port, bodies, times)

			if verbose {
				if err != nil {
					log.Printf("FAIL %+v: %s", pkt, err)
				} else {
					log.Printf("OKAY %+v", pkt)
				}
			}
		}
	}
}

func main() {
	var device, esurl string
	var port, snaplen int

	flag.StringVar(&device, "i", "", "interface")
	flag.StringVar(&esurl, "e", "http://localhost:9200/coiltap", "elastic-url")
	flag.IntVar(&port, "p", 80, "port")
	flag.IntVar(&snaplen, "s", 65535, "snaplen")
	flag.BoolVar(&verbose, "v", false, "snaplen")

	flag.Usage = func() {
		log.Fatalf("usage: %s [ -i interface ] [ -s snaplen ] [ -p port ] [-e elastic-url]", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	devices := []string{}

	if device == "" {
		devs, err := FindAllInterfaces()
		if err != nil {
			log.Fatalf("Couldn't find any devices: %s", err)
		}
		if 0 == len(devs) {
			flag.Usage()
		}
		for _, dev := range devs {
			if len(dev.Addresses) > 0 {
				devices = append(devices, dev.Name)
			}
		}
	} else {
		devices = append(devices, device)
	}

	sink, err := NewSink(esurl)

	if err != nil {
		log.Fatal(err)
	}

	sink.Run()

	for _, device := range devices {
		handle, err := NewHandle(device, port, snaplen)

		if err != nil {
			log.Fatal(err)
		}

		go sniff(handle, sink, port, device)
	}

	select {
	case <-make(chan bool):
	}
}
