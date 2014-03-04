# Coiltap

Coiltap uses [libpcap]() to capture HTTP traffic to and from a local port,
storing the results in ElasticSearch.

## Usage

    coiltap -p 80 -i eth0 http://localhost:9200/requests

## Development

Coiltap doesn't currently work on Vagrant. I'm not sure, but something to do
with the type of packets that are returned on `localhost`. 

## Interface

```go

// For non-encrypted traffic, use
c := SniffHTTP(int port)

// For encrypt traffic, use
c := SniffHTTPS(int port, certFile string, keyFile string)

select {
case p := <- c.Pairs:
  // The full HTTP request
  log.Println("%+v", p.Request)

  // The full HTTP response
  log.Println("%+v", p.Response)

  // Timing contains the following information
  // - Total
  // - Blocked
  // - DNSResolving
  // - Connecting
  // - Sending
  // - Waiting
  // - Receiving
  log.Println("%+v", p.Timing)
}
```
