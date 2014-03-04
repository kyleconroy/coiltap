.PHONY: clean deps

coiltap: *.go libpcap-1.5.3/libpcap.a
	go build .

deps:
	go get -d -v ./...

libpcap-1.5.3/libpcap.a:
	cd libpcap-1.5.3 && ./configure
	cd libpcap-1.5.3 && CFLAGS="-fPIC" make

libpcap-1.5.3:
	wget http://www.tcpdump.org/release/libpcap-1.5.3.tar.gz
	tar -xvf libpcap-1.5.3.tar.gz
	rm -f libpcap-1.5.3.tar.gz

clean:
	rm -f coiltap
	cd libpcap-1.5.3 && make clean
