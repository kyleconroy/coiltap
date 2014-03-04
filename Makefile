.PHONY: clean deps gzip


coiltap: *.go
	go build .

gzip: coiltap
	rm -f coiltap.tar.gz
	tar -cvzf coiltap.tar.gz coiltap

deps:
	go get -d -v ./...

clean:
	rm -f coiltap
