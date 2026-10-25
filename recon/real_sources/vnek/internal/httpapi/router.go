package httpapi

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path/filepath"

	"vnekontakta/internal/domain"
	"vnekontakta/internal/realtime"
	"vnekontakta/internal/social"
)

type API struct {
	service           *social.Service
	webDir, uploadDir string
	hub               *realtime.Hub
}

func New(service *social.Service, webDir, uploadDir string) http.Handler {
	a := &API{service: service, webDir: webDir, uploadDir: uploadDir, hub: realtime.NewHub()}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := service.Store.DB.PingContext(r.Context()); err != nil {
			problem(w, 503, "database unavailable")
			return
		}
		respond(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/api/register", a.register)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/logout", a.logout)
	mux.HandleFunc("/api/me", a.me)
	mux.HandleFunc("/api/users", a.users)
	mux.HandleFunc("/api/profile", a.profile)
	mux.HandleFunc("/api/settings", a.settings)
	mux.HandleFunc("/api/vault/set", a.vaultSet)
	mux.HandleFunc("/api/vault", a.vault)
	mux.HandleFunc("/api/posts", a.posts)
	mux.HandleFunc("/api/posts/like", a.postLike)
	mux.HandleFunc("/api/messages", a.messages)
	mux.HandleFunc("/api/conversations", a.conversations)
	mux.HandleFunc("/api/ws", a.websocket)
	mux.HandleFunc("/uploads/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodError(w)
			return
		}
		if filepath.Base(r.URL.Path) == "uploads" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(a.uploadDir, filepath.Base(r.URL.Path)))
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join(webDir, "static")))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodError(w)
			return
		}
		if len(r.URL.Path) >= 5 && r.URL.Path[:5] == "/api/" {
			problem(w, 404, "Не найдено")
			return
		}
		http.ServeFile(w, r, filepath.Join(a.webDir, "index.html"))
	})
	return mux
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, description string) {
	respond(w, status, map[string]string{"error": description})
}
func methodError(w http.ResponseWriter) { problem(w, 405, "method") }
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		methodError(w)
		return false
	}
	return true
}
func reportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, social.ErrUnauthorized):
		problem(w, 401, "Требуется вход")
	case errors.Is(err, social.ErrNotFound):
		problem(w, 404, "Нет пользователя")
	case errors.Is(err, social.ErrInvalid):
		problem(w, 400, "Некорректные данные")
	case errors.Is(err, social.ErrConflict):
		problem(w, 409, "Логин занят")
	default:
		log.Printf("API error: %v", err)
		problem(w, 500, "Ошибка сервера")
	}
}
func (a *API) sessionID(r *http.Request) string {
	c, err := r.Cookie("sid")
	if err != nil {
		return ""
	}
	return c.Value
}
func (a *API) current(r *http.Request) *domain.User {
	return a.service.Current(r.Context(), a.sessionID(r))
}
func (a *API) requireUser(w http.ResponseWriter, r *http.Request) *domain.User {
	u := a.current(r)
	if u == nil {
		problem(w, 401, "Требуется вход")
	}
	return u
}
func putSession(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
}
