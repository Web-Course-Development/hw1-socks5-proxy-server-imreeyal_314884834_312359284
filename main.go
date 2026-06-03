package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
const (
	socks5Version = 0x05 // VER byte for the SOCKS5 protocol
	authVersion   = 0x01 // VER byte for the username/password sub-negotiation (NOT 0x05)

	methodNoAuth       = 0x00 // "no authentication required"
	methodUserPass     = 0x02 // "username/password" (RFC 1929)
	methodNoAcceptable = 0xFF // server reply: none of the client's methods are acceptable

	cmdConnect = 0x01 // the only command we support

	atypIPv4   = 0x01 // DST.ADDR is 4 raw IPv4 bytes
	atypDomain = 0x03 // DST.ADDR is a 1-byte length followed by the domain name

	// CONNECT reply codes (REP), RFC 1928 §6.
	repSuccess         = 0x00
	repGeneralFailure  = 0x01 // used for any dial failure
	repCommandNotSupp  = 0x07 // command not supported
	repAddrTypeNotSupp = 0x08 // address type not supported
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. Read client greeting and negotiate authentication method.
	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation failed: %v", err)
		return
	}

	// 2. If we selected username/password, run the RFC 1929 sub-negotiation.
	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	// 3-5. Read the CONNECT request, dial the target, send the reply.
	remote, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect failed: %v", err)
		return
	}
	defer remote.Close()

	// 6. Relay data between client and target until both sides are done.
	relay(conn, remote)
}

// negotiateAuth reads the client's SOCKS5 greeting and replies with the
// authentication method the server selected. It returns the selected method so
// the caller knows whether a username/password sub-negotiation must follow.
//
// Greeting (client -> server):  VER | NMETHODS | METHODS[NMETHODS]
// Selection (server -> client): VER | METHOD
func negotiateAuth(conn net.Conn) (byte, error) {
	// Read the 2-byte fixed header: VER and NMETHODS.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("reading greeting header: %w", err)
	}
	if header[0] != socks5Version {
		return 0, fmt.Errorf("unexpected SOCKS version %#x", header[0])
	}
	nmethods := int(header[1])

	// Read exactly NMETHODS method bytes that follow the header.
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("reading methods: %w", err)
	}

	// Decide which method we require. When PROXY_USER is set we demand
	// username/password (RFC 1929); otherwise we accept no-auth.
	want := byte(methodNoAuth)
	if os.Getenv("PROXY_USER") != "" {
		want = methodUserPass
	}

	// Accept only if the client actually offered the method we want.
	for _, m := range methods {
		if m == want {
			if _, err := conn.Write([]byte{socks5Version, want}); err != nil {
				return 0, fmt.Errorf("writing method selection: %w", err)
			}
			return want, nil
		}
	}

	// No common method: tell the client 0xFF and give up on this connection.
	conn.Write([]byte{socks5Version, methodNoAcceptable})
	return methodNoAcceptable, fmt.Errorf("no acceptable auth method (wanted %#x)", want)
}

// authenticateUserPass performs the RFC 1929 username/password sub-negotiation.
// It runs only after negotiateAuth selected methodUserPass (0x02).
//
// Request  (client -> server): VER | ULEN | UNAME | PLEN | PASSWD   (VER = 0x01)
// Response (server -> client): VER | STATUS                          (0x00 = success)
func authenticateUserPass(conn net.Conn) error {
	// Read the 2-byte fixed header: VER (0x01) and ULEN (username length).
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("reading auth header: %w", err)
	}
	if header[0] != authVersion {
		return fmt.Errorf("unexpected auth version %#x (want 0x01)", header[0])
	}

	// Read exactly ULEN username bytes.
	username := make([]byte, header[1])
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("reading username: %w", err)
	}

	// Read PLEN (password length), then exactly PLEN password bytes.
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return fmt.Errorf("reading password length: %w", err)
	}
	password := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	// Compare against the configured credentials.
	if string(username) == os.Getenv("PROXY_USER") && string(password) == os.Getenv("PROXY_PASS") {
		if _, err := conn.Write([]byte{authVersion, 0x00}); err != nil {
			return fmt.Errorf("writing auth success: %w", err)
		}
		return nil
	}

	// Wrong credentials: reply with a non-zero status and fail.
	conn.Write([]byte{authVersion, 0x01})
	return fmt.Errorf("authentication failed for user %q", username)
}

// sendReply writes the 10-byte SOCKS5 CONNECT reply with the given REP code.
// We always report ATYP=IPv4 with an all-zero bound address/port.
func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socks5Version, rep, 0x00, atypIPv4, // VER, REP, RSV, ATYP
		0, 0, 0, 0, // BND.ADDR = 0.0.0.0
		0, 0, // BND.PORT = 0
	}
	_, err := conn.Write(reply)
	return err
}

// handleConnect reads a SOCKS5 CONNECT request, dials the requested target, and
// sends the reply. On success it returns the open connection to the target so
// the caller can relay data; on failure it sends an error reply and returns it.
//
// Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
func handleConnect(conn net.Conn) (net.Conn, error) {
	// Read the 4-byte fixed header: VER, CMD, RSV, ATYP.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("reading connect header: %w", err)
	}
	cmd, atyp := header[1], header[3]

	// We only implement CONNECT.
	if cmd != cmdConnect {
		sendReply(conn, repCommandNotSupp)
		return nil, fmt.Errorf("unsupported command %#x", cmd)
	}

	// Parse DST.ADDR according to the address type.
	var host string
	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("reading IPv4 address: %w", err)
		}
		host = net.IP(addr).String()
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return nil, fmt.Errorf("reading domain length: %w", err)
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return nil, fmt.Errorf("reading domain name: %w", err)
		}
		host = string(name)
	default:
		sendReply(conn, repAddrTypeNotSupp)
		return nil, fmt.Errorf("unsupported address type %#x", atyp)
	}

	// Read the 2-byte big-endian port.
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return nil, fmt.Errorf("reading port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBytes)

	// Dial the target. net.Dial resolves domain names via DNS automatically.
	target := fmt.Sprintf("%s:%d", host, port)
	remote, err := net.Dial("tcp", target)
	if err != nil {
		// Any dial failure
		sendReply(conn, repGeneralFailure)
		return nil, fmt.Errorf("dialing %s: %w", target, err)
	}

	// Success: tell the client the connection is established.
	if err := sendReply(conn, repSuccess); err != nil {
		remote.Close()
		return nil, fmt.Errorf("writing success reply: %w", err)
	}
	return remote, nil
}

// relay copies data in both directions between the client and the target until
// both directions reach EOF. Each direction runs in its own goroutine; when a
// direction finishes, we half-close the destination's write side so the peer
// sees EOF (otherwise an HTTP response would never terminate).
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go copyAndCloseWrite(target, client, &wg) // client -> target (the request)
	go copyAndCloseWrite(client, target, &wg) // target -> client (the response)

	wg.Wait()
}

// copyAndCloseWrite copies everything from src to dst, then signals EOF to dst
// by half-closing its write side. It marks the WaitGroup done when finished.
func copyAndCloseWrite(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()

	io.Copy(dst, src)

	// Send a TCP FIN on dst's write side only, leaving its read side open.
	// CloseWrite is not part of the net.Conn interface, so we type-assert to
	// the (TCP-satisfied) interface that declares it.
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
