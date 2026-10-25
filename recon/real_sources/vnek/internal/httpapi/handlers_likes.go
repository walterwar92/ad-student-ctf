package httpapi

import (
	"errors"
	"net/http"

	"vnekontakta/internal/social"
)

func (a *API) postLike(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "Некорректные данные")
		return
	}
	value := r.FormValue("liked")
	if value != "true" && value != "false" {
		problem(w, 400, "Некорректная отметка")
		return
	}
	state, err := a.service.SetLike(r.Context(), r.FormValue("id"), u.ID, value == "true")
	if errors.Is(err, social.ErrNotFound) {
		problem(w, 404, "Запись не найдена")
		return
	}
	if err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, state)
}
