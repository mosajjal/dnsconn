# dnsconn
DNS Tunneling Implemented as net.Conn in Go

Welcome to `dnsconn` – an innovative experimental project that aims to implement DNS tunneling using Go's `net.Listener` and `net.Conn` interfaces. This project opens up new possibilities for repurposing DNS as a transport layer, allowing for seamless integration of DNS tunneling into existing codebases.

## Test it out

To test the project, you can run the following commands:

```bash
$ # run the server
$ git clone https://github.com/mosajjal/dnsconn
$ cd dnsconn
$ cd example/simple
$ go run server.go
```
  
```bash
$ # run the server
$ git clone https://github.com/mosajjal/dnsconn
$ cd dnsconn
$ cd example/simple
$ go run client.go
```

## EULA

This project is currently distributed under the Server Side Public License (SSPL). This licensing decision is motivated by the following considerations:
  - To prevent potential misuse of the project against non-consenting entities.
  - To avoid unauthorized commercial exploitation under different brands.
  - To ensure proper acknowledgment and referencing of the project's original source.

Happy Hacking! 