.PHONY: clean deps

coiltap: *.go
	go build .

deps:
	go get -d -v ./...

clean:
	rm -f coiltap
