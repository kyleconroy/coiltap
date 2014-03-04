.PHONY: clean deps gzip

coiltap: *.go libpcap-1.5.3/libpcap.a
	go build .

gzip: coiltap
	rm -f coiltap.tar.gz
	tar -cvzf coiltap.tar.gz coiltap

deps:
	go get -d -v ./...

libpcap-1.5.3/libpcap.a:
	wget http://www.tcpdump.org/release/libpcap-1.5.3.tar.gz
	tar -xvf libpcap-1.5.3.tar.gz
	rm -f libpcap-1.5.3.tar.gz
	cd libpcap-1.5.3 && ./configure
	cd libpcap-1.5.3 && CFLAGS="-fPIC" make

clean:
	rm -f coiltap
	cd libpcap-1.5.3 && make clean
