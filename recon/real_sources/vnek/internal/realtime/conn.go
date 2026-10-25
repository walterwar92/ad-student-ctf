package realtime

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const maxPayload = 16384
const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

var ErrClosed = errors.New("websocket closed")

type Conn struct {
	socket    net.Conn
	reader    *bufio.Reader
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func headerHas(s, token string) bool {
	for _, field := range strings.Split(s, ",") {
		if strings.EqualFold(strings.TrimSpace(field), token) {
			return true
		}
	}
	return false
}

func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if r.Method != http.MethodGet || !headerHas(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "WebSocket upgrade required", http.StatusBadRequest)
		return nil, ErrClosed
	}
	rawKey, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if err != nil || len(rawKey) != 16 {
		http.Error(w, "Invalid websocket key", http.StatusBadRequest)
		return nil, ErrClosed
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || !strings.EqualFold(parsed.Host, r.Host) {
			http.Error(w, "Origin denied", http.StatusForbidden)
			return nil, ErrClosed
		}
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Websocket not supported", http.StatusInternalServerError)
		return nil, ErrClosed
	}
	socket, buffer, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}
	accept := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + websocketGUID))
	_, err = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(accept[:]))
	if err == nil {
		err = buffer.Flush()
	}
	if err != nil {
		socket.Close()
		return nil, err
	}
	return &Conn{socket: socket, reader: buffer.Reader}, nil
}

func (c *Conn) writeFrame(opcode byte, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.socket.SetWriteDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	header := []byte{0x80 | opcode}
	switch {
	case len(data) < 126:
		header = append(header, byte(len(data)))
	case len(data) <= 65535:
		header = append(header, 126, byte(len(data)>>8), byte(len(data)))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(len(data)>>24), byte(len(data)>>16), byte(len(data)>>8), byte(len(data)))
	}
	if _, err := c.socket.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		_, err := c.socket.Write(data)
		return err
	}
	return nil
}

func (c *Conn) WriteJSON(data any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return c.writeFrame(1, encoded)
}

func (c *Conn) WriteText(data []byte) error { return c.writeFrame(1, data) }
func (c *Conn) Ping() error                 { return c.writeFrame(9, []byte("ping")) }
func (c *Conn) Close()                      { c.closeOnce.Do(func() { _ = c.socket.Close() }) }

func (c *Conn) ReadJSON(value any) error {
	payload, err := c.readText()
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, value)
}

func (c *Conn) readText() ([]byte, error) {
	var result bytes.Buffer
	started := false
	for {
		if err := c.socket.SetReadDeadline(time.Now().Add(75 * time.Second)); err != nil {
			return nil, err
		}
		var head [2]byte
		if _, err := io.ReadFull(c.reader, head[:]); err != nil {
			return nil, err
		}
		fin, op := head[0]&0x80 != 0, head[0]&0x0f
		if head[0]&0x70 != 0 || head[1]&0x80 == 0 {
			return nil, ErrClosed
		}
		size := uint64(head[1] & 0x7f)
		switch size {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.reader, b[:]); err != nil {
				return nil, err
			}
			size = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.reader, b[:]); err != nil {
				return nil, err
			}
			size = binary.BigEndian.Uint64(b[:])
		}
		if size > maxPayload || uint64(result.Len())+size > maxPayload {
			return nil, ErrClosed
		}
		if op >= 8 && (!fin || size > 125) {
			return nil, ErrClosed
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return nil, err
		}
		payload := make([]byte, int(size))
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return nil, err
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch op {
		case 8:
			_ = c.writeFrame(8, nil)
			return nil, io.EOF
		case 9:
			if err := c.writeFrame(10, payload); err != nil {
				return nil, err
			}
			continue
		case 10:
			continue
		case 1:
			if started {
				return nil, ErrClosed
			}
			started = true
		case 0:
			if !started {
				return nil, ErrClosed
			}
		default:
			return nil, ErrClosed
		}
		_, _ = result.Write(payload)
		if fin {
			if !utf8.Valid(result.Bytes()) {
				return nil, ErrClosed
			}
			return result.Bytes(), nil
		}
	}
}
