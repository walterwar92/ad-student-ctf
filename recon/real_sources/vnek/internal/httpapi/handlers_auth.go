package httpapi

import (
	"net/http"
)

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "Неверная форма")
		return
	}
	u, token, err := a.service.Register(r.Context(), r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		reportError(w, err)
		return
	}
	putSession(w, token)
	respond(w, 200, map[string]any{"ok": true, "uuid": u.ID})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "Неверная форма")
		return
	}
	token, err := a.service.Login(r.Context(), r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		reportError(w, err)
		return
	}
	putSession(w, token)
	respond(w, 200, map[string]bool{"ok": true})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	a.service.Logout(r.Context(), a.sessionID(r))
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	respond(w, 200, map[string]bool{"ok": true})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	respond(w, 200, map[string]any{"id": u.ID, "username": u.Name, "display": u.Display, "bio": u.Bio, "created": publicCreated(u), "vault": u.Secret})
}
