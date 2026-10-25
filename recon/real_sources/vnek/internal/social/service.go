package social

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"vnekontakta/internal/domain"
	"vnekontakta/internal/identity"
	"vnekontakta/internal/media"
	"vnekontakta/internal/repository"
)

var (
	ErrUnauthorized = errors.New("authentication required")
	ErrNotFound     = errors.New("not found")
	ErrInvalid      = errors.New("invalid input")
	ErrConflict     = errors.New("username taken")
)

type Service struct {
	Store  *repository.Store
	IDs    *identity.Generator
	Images media.Processor
}

func validName(s string) bool {
	if len(s) < 3 || len(s) > 25 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func passwordHash(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(derive([]byte(password), salt))
}

func derive(password, salt []byte) []byte {
	mac := hmac.New(sha256.New, password)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	block := mac.Sum(nil)
	out := append([]byte(nil), block...)
	for i := 1; i < 160000; i++ {
		mac = hmac.New(sha256.New, password)
		mac.Write(block)
		block = mac.Sum(nil)
		for j := range out {
			out[j] ^= block[j]
		}
	}
	return out
}

func passwordMatches(stored, password string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 2 {
		return false
	}
	salt, e1 := hex.DecodeString(parts[0])
	expected, e2 := hex.DecodeString(parts[1])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(expected) != 32 {
		return false
	}
	actual := derive([]byte(password), salt)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func repoErr(err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return ErrNotFound
	}
	if errors.Is(err, repository.ErrConflict) {
		return ErrConflict
	}
	return err
}

func (s *Service) Current(ctx context.Context, token string) *domain.User {
	if token == "" {
		return nil
	}
	u, err := s.Store.SessionUser(ctx, token)
	if err != nil {
		return nil
	}
	return u
}

func (s *Service) Register(ctx context.Context, username, password string) (domain.User, string, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	if !validName(username) || len(password) < 6 || len(password) > 128 {
		return domain.User{}, "", ErrInvalid
	}
	id, err := s.IDs.Next()
	if err != nil {
		return domain.User{}, "", err
	}
	created, err := identity.CreatedAt(id)
	if err != nil {
		return domain.User{}, "", err
	}
	u := domain.User{ID: id, Name: username, Display: username, Password: passwordHash(password), Created: created}
	if err := s.Store.CreateUser(ctx, u); err != nil {
		return domain.User{}, "", repoErr(err)
	}
	token := identity.RandomToken()
	if err := s.Store.CreateSession(ctx, token, id); err != nil {
		return domain.User{}, "", err
	}
	return u, token, nil
}

func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	u, err := s.Store.UserByName(ctx, strings.ToLower(strings.TrimSpace(username)))
	if err != nil || !passwordMatches(u.Password, password) {
		return "", ErrUnauthorized
	}
	token := identity.RandomToken()
	if err = s.Store.CreateSession(ctx, token, u.ID); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) Logout(ctx context.Context, token string) {
	if token != "" {
		_ = s.Store.DeleteSession(ctx, token)
	}
}

func (s *Service) UpdateSettings(ctx context.Context, id, display, bio string) error {
	display = strings.TrimSpace(display)
	if len([]rune(display)) > 60 || len([]rune(bio)) > 500 || display == "" {
		return ErrInvalid
	}
	return repoErr(s.Store.UpdateSettings(ctx, id, display, bio))
}

func (s *Service) SetVault(ctx context.Context, id, secret string) error {
	if len(secret) > 512 {
		return ErrInvalid
	}
	return repoErr(s.Store.UpdateVault(ctx, id, secret))
}

func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (s *Service) Vault(ctx context.Context, uuid string) (*domain.User, error) {
	if !validUUID(uuid) {
		return nil, ErrNotFound
	}
	u, err := s.Store.UserByID(ctx, uuid)
	return u, repoErr(err)
}

func (s *Service) Profile(ctx context.Context, username string) (*domain.User, error) {
	u, err := s.Store.UserByName(ctx, username)
	return u, repoErr(err)
}

func (s *Service) Users(ctx context.Context) ([]domain.User, error) { return s.Store.Users(ctx) }

func (s *Service) Conversations(ctx context.Context, userID string) ([]repository.ConversationContact, error) {
	return s.Store.Conversations(ctx, userID)
}

func (s *Service) ListPosts(ctx context.Context, viewerID string) ([]repository.PostView, error) {
	return s.Store.Posts(ctx, viewerID)
}

func (s *Service) SetLike(ctx context.Context, postID, userID string, liked bool) (repository.LikeState, error) {
	if len(postID) < 1 || len(postID) > 128 {
		return repository.LikeState{}, ErrInvalid
	}
	state, err := s.Store.SetLike(ctx, postID, userID, liked)
	return state, repoErr(err)
}

func (s *Service) CreatePost(ctx context.Context, userID, text, photo string) error {
	text = strings.TrimSpace(text)
	if len([]rune(text)) > 2000 || (text == "" && photo == "") {
		return ErrInvalid
	}
	return s.Store.CreatePost(ctx, identity.RandomToken(), userID, text, photo)
}

func (s *Service) ListMessages(ctx context.Context, userID, with, after string) ([]repository.MessageView, error) {
	if with == "" {
		return []repository.MessageView{}, nil
	}
	if len(after) > 128 {
		return nil, ErrInvalid
	}
	return s.Store.Messages(ctx, userID, with, after)
}

func (s *Service) SendMessage(ctx context.Context, userID, to, text string) error {
	_, _, err := s.SendMessageDetailed(ctx, userID, to, text)
	return err
}

func (s *Service) SendMessageDetailed(ctx context.Context, userID, to, text string) (repository.MessageView, string, error) {
	text = strings.TrimSpace(text)
	if len([]rune(text)) < 1 || len([]rune(text)) > 2000 || !validName(to) {
		return repository.MessageView{}, "", ErrInvalid
	}
	msg, receiver, err := s.Store.CreateMessage(ctx, identity.RandomToken(), userID, to, text)
	return msg, receiver, repoErr(err)
}

func (s *Service) Cleanup(ctx context.Context, ttl time.Duration) error {
	photos, err := s.Store.Cleanup(ctx, ttl)
	if err != nil {
		return err
	}
	for _, photo := range photos {
		s.Images.Delete(photo)
	}
	return nil
}
