package httpapi

import "net/http"

func (a *API) conversations(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	contacts, err := a.service.Conversations(r.Context(), u.ID)
	if err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, contacts)
}

func (a *API) messages(w http.ResponseWriter, r *http.Request) {
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	if r.Method == http.MethodGet {
		messages, err := a.service.ListMessages(r.Context(), u.ID, r.URL.Query().Get("with"), r.URL.Query().Get("after"))
		if err != nil {
			reportError(w, err)
			return
		}
		respond(w, 200, messages)
		return
	}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "Неверная форма")
		return
	}
	msg, recipientID, err := a.service.SendMessageDetailed(r.Context(), u.ID, r.FormValue("to"), r.FormValue("text"))
	if err != nil {
		reportError(w, err)
		return
	}
	a.hub.Publish([]string{u.ID, recipientID}, map[string]any{"type": "message", "message": msg})
	respond(w, 200, map[string]bool{"ok": true})
}
