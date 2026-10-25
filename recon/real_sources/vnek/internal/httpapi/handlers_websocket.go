package httpapi

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"vnekontakta/internal/realtime"
	"vnekontakta/internal/social"
)

type incomingEvent struct {
	Type     string `json:"type"`
	To       string `json:"to"`
	Text     string `json:"text"`
	ClientID string `json:"client_id"`
}

func (a *API) websocket(w http.ResponseWriter, r *http.Request) {
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	conn, err := realtime.Upgrade(w, r)
	if err != nil {
		return
	}
	client := a.hub.Join(u.ID, conn)
	defer a.hub.Leave(u.ID, client)
	go client.RunWriter()
	client.Queue(map[string]any{"type": "ready"})
	for {
		var in incomingEvent
		if err := conn.ReadJSON(&in); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, realtime.ErrClosed) {
				log.Printf("websocket read: %v", err)
			}
			return
		}
		if in.Type != "send" {
			client.Queue(map[string]any{"type": "error", "client_id": in.ClientID, "error": "Неизвестная команда"})
			continue
		}
		if len(in.ClientID) > 80 {
			client.Queue(map[string]any{"type": "error", "error": "Неверный идентификатор запроса"})
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		msg, receiverID, err := a.service.SendMessageDetailed(ctx, u.ID, in.To, in.Text)
		cancel()
		if err != nil {
			description := "Не удалось отправить сообщение"
			if errors.Is(err, social.ErrInvalid) {
				description = "Сообщение должно содержать от 1 до 2000 символов"
			}
			if errors.Is(err, social.ErrNotFound) {
				description = "Собеседник не найден"
			}
			client.Queue(map[string]any{"type": "error", "client_id": in.ClientID, "error": description})
			continue
		}
		client.Queue(map[string]any{"type": "ack", "client_id": in.ClientID, "message": msg})
		a.hub.Publish([]string{u.ID, receiverID}, map[string]any{"type": "message", "message": msg})
	}
}
