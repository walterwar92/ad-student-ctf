package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"vnekontakta/internal/domain"
	"vnekontakta/internal/identity"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct{ DB *sql.DB }

func Open(ctx context.Context, url, migrationPath string) (*Store, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err = db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	sqlBytes, err := os.ReadFile(migrationPath)
	if err != nil {
		db.Close()
		return nil, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, statement := range strings.Split(string(sqlBytes), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			_ = tx.Rollback()
			db.Close()
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) UUIDSeed(ctx context.Context) ([]byte, error) {
	seed, err := identity.Seed()
	if err != nil {
		return nil, err
	}
	if _, err = s.DB.ExecContext(ctx, "INSERT INTO app_meta(key,value) VALUES('uuid_seed',$1) ON CONFLICT(key) DO NOTHING", seed); err != nil {
		return nil, err
	}
	var stored []byte
	err = s.DB.QueryRowContext(ctx, "SELECT value FROM app_meta WHERE key='uuid_seed'").Scan(&stored)
	return stored, err
}

func scanUser(row interface{ Scan(...any) error }) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Name, &u.Display, &u.Password, &u.Bio, &u.Secret, &u.Created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const selectUser = "SELECT id,username,display_name,password_hash,bio,secret,created_at FROM users"

func (s *Store) UserByID(ctx context.Context, id string) (*domain.User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, selectUser+" WHERE id::text=$1", id))
}

func (s *Store) UserByName(ctx context.Context, name string) (*domain.User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, selectUser+" WHERE username=$1", name))
}

func (s *Store) CreateUser(ctx context.Context, u domain.User) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO users(id,username,display_name,password_hash,bio,secret,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)", u.ID, u.Name, u.Display, u.Password, u.Bio, u.Secret, u.Created)
	if err != nil && isDuplicate(err) {
		return ErrConflict
	}
	return err
}

func isDuplicate(err error) bool {
	type sqlState interface{ SQLState() string }
	var pg sqlState
	return errors.As(err, &pg) && pg.SQLState() == "23505"
}

func (s *Store) CreateSession(ctx context.Context, token, id string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO sessions(token,user_id,expires_at) VALUES($1,$2,$3)", token, id, time.Now().Add(24*time.Hour))
	return err
}

func (s *Store) SessionUser(ctx context.Context, token string) (*domain.User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, selectUser+" JOIN sessions s ON s.user_id=users.id WHERE s.token=$1 AND s.expires_at>NOW()", token))
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE token=$1", token)
	return err
}

func (s *Store) UpdateSettings(ctx context.Context, id, display, bio string) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE users SET display_name=$1,bio=$2 WHERE id::text=$3", display, bio, id)
	return updateResult(r, err)
}

func (s *Store) UpdateVault(ctx context.Context, id, secret string) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE users SET secret=$1 WHERE id::text=$2", secret, id)
	return updateResult(r, err)
}

func updateResult(r sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Users(ctx context.Context) ([]domain.User, error) {
	rows, err := s.DB.QueryContext(ctx, selectUser+" ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.User, 0)
	for rows.Next() {
		u, e := scanUser(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// ConversationContact is a user with whom the account has exchanged messages.
type ConversationContact struct{ Name, Display string }

func (s *Store) Conversations(ctx context.Context, userID string) ([]ConversationContact, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT u.username, u.display_name
 FROM users u JOIN (
   SELECT CASE WHEN from_id=$1::uuid THEN to_id ELSE from_id END AS partner_id,
          MAX(created_at) AS last_message
   FROM messages
   WHERE from_id=$1::uuid OR to_id=$1::uuid
   GROUP BY partner_id
 ) recent ON recent.partner_id=u.id
 ORDER BY recent.last_message DESC, u.username ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ConversationContact, 0)
	for rows.Next() {
		var contact ConversationContact
		if err := rows.Scan(&contact.Name, &contact.Display); err != nil {
			return nil, err
		}
		out = append(out, contact)
	}
	return out, rows.Err()
}

func (s *Store) Posts(ctx context.Context, viewerID string) ([]PostView, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT p.id,u.username,u.display_name,p.body,p.photo_url,p.created_at,
(SELECT COUNT(*) FROM post_likes l WHERE l.post_id=p.id),
EXISTS(SELECT 1 FROM post_likes l WHERE l.post_id=p.id AND l.user_id::text=$1)
FROM posts p JOIN users u ON u.id=p.author_id
ORDER BY p.created_at DESC,p.id DESC LIMIT 100`, viewerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PostView, 0)
	for rows.Next() {
		var p PostView
		var created time.Time
		if e := rows.Scan(&p.ID, &p.Author, &p.Display, &p.Text, &p.Photo, &created, &p.Likes, &p.Liked); e != nil {
			return nil, e
		}
		p.Created = created.UTC().Format("02.01.2006 15:04")
		out = append(out, p)
	}
	return out, rows.Err()
}

type PostView struct {
	ID, Author, Display, Text, Photo, Created string
	Likes                                     int64
	Liked                                     bool
}

type LikeState struct {
	Likes int64 `json:"likes"`
	Liked bool  `json:"liked"`
}

func (s *Store) SetLike(ctx context.Context, postID, userID string, liked bool) (LikeState, error) {
	if liked {
		_, err := s.DB.ExecContext(ctx, `INSERT INTO post_likes(post_id,user_id)
SELECT id,$2::uuid FROM posts WHERE id=$1
ON CONFLICT(post_id,user_id) DO NOTHING`, postID, userID)
		if err != nil {
			return LikeState{}, err
		}
	} else {
		if _, err := s.DB.ExecContext(ctx, "DELETE FROM post_likes WHERE post_id=$1 AND user_id::text=$2", postID, userID); err != nil {
			return LikeState{}, err
		}
	}
	var state LikeState
	err := s.DB.QueryRowContext(ctx, `SELECT
(SELECT COUNT(*) FROM post_likes WHERE post_id=p.id),
EXISTS(SELECT 1 FROM post_likes WHERE post_id=p.id AND user_id::text=$2)
FROM posts p WHERE p.id=$1`, postID, userID).Scan(&state.Likes, &state.Liked)
	if errors.Is(err, sql.ErrNoRows) {
		return LikeState{}, ErrNotFound
	}
	return state, err
}

func (s *Store) CreatePost(ctx context.Context, id, author, text, photo string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO posts(id,author_id,body,photo_url) VALUES($1,$2,$3,$4)", id, author, text, photo)
	return err
}

type MessageView struct{ ID, From, To, Text, Created string }

func (s *Store) Messages(ctx context.Context, userID, otherName, after string) ([]MessageView, error) {
	const source = `FROM messages m JOIN users f ON f.id=m.from_id JOIN users t ON t.id=m.to_id
WHERE ((m.from_id::text=$1 AND t.username=$2) OR (m.to_id::text=$1 AND f.username=$2))`
	const cols = "m.id,f.username,t.username,m.body,m.created_at"
	var rows *sql.Rows
	var err error
	if after == "" {
		rows, err = s.DB.QueryContext(ctx, `SELECT id,username_from,username_to,body,created_at FROM
(SELECT m.id,f.username AS username_from,t.username AS username_to,m.body,m.created_at `+source+`
ORDER BY m.created_at DESC,m.id DESC LIMIT 250) recent
ORDER BY created_at ASC,id ASC`, userID, otherName)
	} else {
		rows, err = s.DB.QueryContext(ctx, `SELECT `+cols+` `+source+`
AND (m.created_at,m.id) > (SELECT anchor.created_at,anchor.id FROM messages anchor
WHERE anchor.id=$3 AND ((anchor.from_id::text=$1 AND anchor.to_id=(SELECT id FROM users WHERE username=$2))
OR (anchor.to_id::text=$1 AND anchor.from_id=(SELECT id FROM users WHERE username=$2))))
ORDER BY m.created_at ASC,m.id ASC LIMIT 250`, userID, otherName, after)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]MessageView, 0)
	for rows.Next() {
		var m MessageView
		var created time.Time
		if e := rows.Scan(&m.ID, &m.From, &m.To, &m.Text, &created); e != nil {
			return nil, e
		}
		m.Created = created.UTC().Format("02.01 15:04")
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) CreateMessage(ctx context.Context, id, from, toName, body string) (MessageView, string, error) {
	var msg MessageView
	var recipientID string
	var created time.Time
	err := s.DB.QueryRowContext(ctx, `WITH recipient AS (
        SELECT id FROM users WHERE username=$4
    ), inserted AS (
        INSERT INTO messages(id,from_id,to_id,body)
        SELECT $1,$2::uuid,recipient.id,$3 FROM recipient
        RETURNING id,from_id,to_id,body,created_at
    )
    SELECT m.id,f.username,t.username,m.body,m.created_at,m.to_id::text
    FROM inserted m
    JOIN users f ON f.id=m.from_id
    JOIN users t ON t.id=m.to_id`, id, from, body, toName).Scan(&msg.ID, &msg.From, &msg.To, &msg.Text, &created, &recipientID)
	if errors.Is(err, sql.ErrNoRows) {
		return MessageView{}, "", ErrNotFound
	}
	if err != nil {
		return MessageView{}, "", err
	}
	msg.Created = created.UTC().Format("02.01 15:04")
	return msg, recipientID, nil
}

func (s *Store) Cleanup(ctx context.Context, ttl time.Duration) ([]string, error) {
	cut := time.Now().Add(-ttl)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	photos := make([]string, 0)
	rows, err := tx.QueryContext(ctx, "SELECT photo_url FROM posts WHERE created_at<$1 OR author_id IN (SELECT id FROM users WHERE created_at<$1)", cut)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var photo string
		if e := rows.Scan(&photo); e != nil {
			rows.Close()
			return nil, e
		}
		if photo != "" {
			photos = append(photos, photo)
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for _, query := range []string{
		"DELETE FROM posts WHERE created_at<$1",
		"DELETE FROM messages WHERE created_at<$1",
		"DELETE FROM users WHERE created_at<$1",
	} {
		if _, err = tx.ExecContext(ctx, query, cut); err != nil {
			return nil, fmt.Errorf("cleanup: %w", err)
		}
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<NOW()"); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return photos, nil
}
