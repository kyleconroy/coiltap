package main

import (
	"bufio"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/tcpassembly"
	"code.google.com/p/gopacket/tcpassembly/tcpreader"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

var verbose bool

type httpStreamFactory struct {
	port int
}

type requestStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

type responseStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (f httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
    src := transport.Src().String()
	if src == strconv.Itoa(f.port) {
		hstream := &responseStream{
			net:       net,
			transport: transport,
			r:         tcpreader.NewReaderStream(),
		}
		go hstream.run()
		return &hstream.r
	} else {
		hstream := &requestStream{
			net:       net,
			transport: transport,
			r:         tcpreader.NewReaderStream(),
		}
		go hstream.run()
		return &hstream.r
	}
}

func (h *responseStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		_, err := buf.Peek(1)
		if err == io.EOF {
			return
		}
		res, err := http.ReadResponse(buf, nil)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(res.Body)
			res.Body.Close()
			log.Println("Received response from stream", h.net, h.transport, ":", res, "with", bodyBytes, "bytes in request body")
		}
	}
}

func (h *requestStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		_, err := buf.Peek(1)
		if err == io.EOF {
			return
		}
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
}

func listen(iface net.Interface, port int) {
	snaplen := 65535
	handle, err := OpenLive(iface.Name, int32(snaplen), true, time.Second*1)

	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter("tcp and port " + strconv.Itoa(port))

	log.Printf("Listening to HTTP traffic on port %d on interface %s", port, iface.Name)

	if err != nil {
		log.Fatal(err)
	}

	factory := httpStreamFactory{port: port}
	pool := tcpassembly.NewStreamPool(&factory)
	assembler := tcpassembly.NewAssembler(pool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
				log.Println("Unusable packet")
				continue
			}
			tcp := packet.TransportLayer().(*layers.TCP)
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
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
		go listen(iface, port)
	}

	select {
	case <-make(chan bool):
	}
}
