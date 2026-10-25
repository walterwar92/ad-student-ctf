package httpapi

import (
	"net/http"
	"time"

	"vnekontakta/internal/domain"
	"vnekontakta/internal/identity"
)

func publicCreated(u *domain.User) string {
	created, err := identity.CreatedAt(u.ID)
	if err != nil {
		created = u.Created.UTC()
	}
	return created.Format(time.RFC3339Nano)
}

func (a *API) users(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	type public struct{ Name, Display, Created string }
	users, err := a.service.Users(r.Context())
	if err != nil {
		reportError(w, err)
		return
	}
	out := make([]public, 0, len(users))
	for _, u := range users {
		out = append(out, public{u.Name, u.Display, publicCreated(&u)})
	}
	respond(w, 200, out)
}

func (a *API) profile(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	u, err := a.service.Profile(r.Context(), r.URL.Query().Get("username"))
	if err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, map[string]any{"username": u.Name, "display": u.Display, "bio": u.Bio, "created": publicCreated(u)})
}

func (a *API) settings(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "Неверная форма")
		return
	}
	if err := a.service.UpdateSettings(r.Context(), u.ID, r.FormValue("display"), r.FormValue("bio")); err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
