package httpapi

import "net/http"

func (a *API) vaultSet(w http.ResponseWriter, r *http.Request) {
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
	if err := a.service.SetVault(r.Context(), u.ID, r.FormValue("secret")); err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"ok": true})
}

func (a *API) vault(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	// SECURITY FIX (pre-game audit): this endpoint previously returned ANY user's
	// secret for an arbitrary ?uuid= query parameter with NO authentication check
	// at all. Combined with the fact that identity.Generator emits UUIDv1 values
	// (fixed node/clock-seq per process + a timestamp that is itself exposed
	// verbatim via the public "Created" field on /api/users and /api/profile),
	// any remote, unauthenticated caller could reconstruct a victim's exact UUID
	// from public data and read their vault secret directly (full flag theft).
	// Now the caller must be authenticated and may only read their OWN vault.
	u := a.requireUser(w, r)
	if u == nil {
		return
	}
	requested := r.URL.Query().Get("uuid")
	if requested != "" && requested != u.ID {
		problem(w, 403, "Можно смотреть только свой секрет")
		return
	}
	self, err := a.service.Vault(r.Context(), u.ID)
	if err != nil {
		reportError(w, err)
		return
	}
	respond(w, 200, map[string]string{"uuid": self.ID, "secret": self.Secret})
}
