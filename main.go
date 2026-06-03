package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// SOCKS5 protocol constants (RFC 1928 / RFC 1929).
const (
	socks5Version = 0x05 // VER byte for the SOCKS5 protocol
	authVersion   = 0x01 // VER byte for the username/password sub-negotiation (NOT 0x05)

	methodNoAuth       = 0x00 // "no authentication required"
	methodUserPass     = 0x02 // "username/password" (RFC 1929)
	methodNoAcceptable = 0xFF // server reply: none of the client's methods are acceptable
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

	// TODO (next steps):
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target
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
