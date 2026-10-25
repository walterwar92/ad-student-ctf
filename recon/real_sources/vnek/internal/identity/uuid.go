package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Generator struct{}

func RandomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func Seed() ([]byte, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	b[0] = 0x02
	return b, nil
}

func New(seed []byte) (*Generator, error) {
	if len(seed) != 8 {
		return nil, fmt.Errorf("invalid UUID seed")
	}
	if !uuid.SetNodeID(seed[:6]) {
		return nil, fmt.Errorf("invalid identifier configuration")
	}
	uuid.SetClockSequence(int(seed[6])<<8 | int(seed[7]))
	return &Generator{}, nil
}

func (g *Generator) Next() (string, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func CreatedAt(text string) (time.Time, error) {
	id, err := uuid.Parse(text)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid UUID: %w", err)
	}
	if id.Version() != 1 {
		return time.Time{}, fmt.Errorf("UUID does not contain a v1 timestamp")
	}
	sec, nsec := id.Time().UnixTime()
	return time.Unix(sec, nsec).UTC(), nil
}
