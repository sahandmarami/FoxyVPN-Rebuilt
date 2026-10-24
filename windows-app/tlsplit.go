package main

// TLS ClientHello splitter (port of TlsClientHelloSplitter.kt).
// Splits the first TLS handshake write into small segments so that DPI boxes
// which only inspect the first packet cannot easily match the ClientHello.

import (
	"encoding/binary"
	"net"
)

type splitConn struct {
	net.Conn
	mode     string // "first-byte" or "sni"
	splitDone bool
}

func looksLikeClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func findSniOffset(b []byte) (int, int, bool) {
	if len(b) < 44 || b[0] != 0x16 {
		return 0, 0, false
	}
	curr := 5
	if b[curr] != 0x01 {
		return 0, 0, false
	}
	curr += 4
	curr += 2 + 32
	if curr >= len(b) {
		return 0, 0, false
	}
	sessionIDLen := int(b[curr])
	curr += 1 + sessionIDLen
	if curr+2 > len(b) {
		return 0, 0, false
	}
	cipherLen := int(binary.BigEndian.Uint16(b[curr : curr+2]))
	curr += 2 + cipherLen
	if curr >= len(b) {
		return 0, 0, false
	}
	compLen := int(b[curr])
	curr += 1 + compLen
	if curr+2 > len(b) {
		return 0, 0, false
	}
	extLen := int(binary.BigEndian.Uint16(b[curr : curr+2]))
	extEnd := curr + 2 + extLen
	curr += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}
	for curr+4 <= extEnd {
		extType := binary.BigEndian.Uint16(b[curr : curr+2])
		extLen := int(binary.BigEndian.Uint16(b[curr+2 : curr+4]))
		body := curr + 4
		if body+extLen > extEnd {
			return 0, 0, false
		}
		if extType == 0 { // server_name
			if extLen < 2 {
				return 0, 0, false
			}
			listLen := int(binary.BigEndian.Uint16(b[body : body+2]))
			list := body + 2
			if list+listLen > body+extLen {
				return 0, 0, false
			}
			if listLen < 3 || b[list] != 0 {
				return 0, 0, false
			}
			nameLen := int(binary.BigEndian.Uint16(b[list+1 : list+3]))
			start := list + 3
			end := start + nameLen
			if end > list+listLen || end > len(b) {
				return 0, 0, false
			}
			return start, end, true
		}
		curr = body + extLen
	}
	return 0, 0, false
}

func (c *splitConn) Write(b []byte) (int, error) {
	if c.splitDone || !looksLikeClientHello(b) {
		return c.Conn.Write(b)
	}
	c.splitDone = true
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	switch c.mode {
	case "first-byte":
		if _, err := c.Conn.Write(b[:1]); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(b[1:]); err != nil {
			return 1, err
		}
		return len(b), nil
	case "sni":
		start, _, ok := findSniOffset(b)
		if !ok || start <= 0 || start >= len(b) {
			return c.Conn.Write(b)
		}
		if _, err := c.Conn.Write(b[:start]); err != nil {
			return 0, err
		}
		if _, err := c.Conn.Write(b[start : start+1]); err != nil {
			return start, err
		}
		if _, err := c.Conn.Write(b[start+1:]); err != nil {
			return start + 1, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}
