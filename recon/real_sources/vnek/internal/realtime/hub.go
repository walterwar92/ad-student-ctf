package realtime

import (
	"encoding/json"
	"sync"
	"time"
)

type Client struct {
	Conn *Conn
	Send chan []byte
	stop chan struct{}
	once sync.Once
}

func (c *Client) Close() {
	c.once.Do(func() { close(c.stop); c.Conn.Close() })
}

func (c *Client) Queue(event any) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	select {
	case <-c.stop:
	case c.Send <- data:
	default:
		c.Close()
	}
}

func (c *Client) RunWriter() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()
	defer c.Close()
	for {
		select {
		case <-c.stop:
			return
		case data := <-c.Send:
			if err := c.Conn.WriteText(data); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.Conn.Ping(); err != nil {
				return
			}
		}
	}
}

type Hub struct {
	mu     sync.RWMutex
	byUser map[string]map[*Client]struct{}
}

func NewHub() *Hub { return &Hub{byUser: make(map[string]map[*Client]struct{})} }

func (h *Hub) Join(userID string, conn *Conn) *Client {
	c := &Client{Conn: conn, Send: make(chan []byte, 64), stop: make(chan struct{})}
	h.mu.Lock()
	if h.byUser[userID] == nil {
		h.byUser[userID] = make(map[*Client]struct{})
	}
	h.byUser[userID][c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *Hub) Leave(userID string, c *Client) {
	h.mu.Lock()
	if clients := h.byUser[userID]; clients != nil {
		delete(clients, c)
		if len(clients) == 0 {
			delete(h.byUser, userID)
		}
	}
	h.mu.Unlock()
	c.Close()
}

func (h *Hub) Publish(ids []string, event any) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	h.mu.RLock()
	seen := make(map[*Client]struct{})
	for _, id := range ids {
		for c := range h.byUser[id] {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			select {
			case <-c.stop:
			case c.Send <- data:
			default:
				c.Close()
			}
		}
	}
	h.mu.RUnlock()
}
