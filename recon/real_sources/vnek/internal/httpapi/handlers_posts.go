package httpapi

import (
	"errors"
	"net/http"

	"vnekontakta/internal/media"
)

func (a *API) posts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		viewerID := ""
		if user := a.current(r); user != nil {
			viewerID = user.ID
		}
		posts, err := a.service.ListPosts(r.Context(), viewerID)
		if err != nil {
			reportError(w, err)
			return
		}
		respond(w, 200, posts)
		return
	}
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 6<<20)
	if err := r.ParseMultipartForm(5 << 20); err != nil {
		problem(w, 400, "Слишком большой запрос")
		return
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	text := r.FormValue("text")
	if len(text) > 2000 {
		problem(w, 400, "Слишком длинный пост")
		return
	}
	photo := ""
	file, head, err := r.FormFile("image")
	if err == nil {
		defer file.Close()
		if head.Size > media.MaxImageBytes {
			problem(w, 400, "Максимум 5 MB")
			return
		}
		photo, err = a.service.Images.Process(r.Context(), file, u.ID)
		if err != nil {
			problem(w, 400, "Невозможно обработать изображение")
			return
		}
	} else if !errors.Is(err, http.ErrMissingFile) {
		problem(w, 400, "Ошибка загрузки")
		return
	}
	if err := a.service.CreatePost(r.Context(), u.ID, text, photo); err != nil {
		a.service.Images.Delete(photo)
		reportError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}
