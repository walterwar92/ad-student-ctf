package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port          string
	DatabaseURL   string
	MigrationPath string
	UploadDir     string
	WebDir        string
	WorkerPath    string
	TTL           time.Duration
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func Load() Config {
	ttl := 30 * time.Minute
	if sec, err := strconv.Atoi(os.Getenv("TTL_SECONDS")); err == nil && sec > 0 {
		ttl = time.Duration(sec) * time.Second
	}
	return Config{
		Port:          env("PORT", "8080"),
		DatabaseURL:   env("DATABASE_URL", "postgres://vnekontakta:vnekontakta@localhost:5432/vnekontakta?sslmode=disable"),
		MigrationPath: env("MIGRATION_PATH", "migrations/001_init.sql"),
		UploadDir:     env("UPLOAD_DIR", "uploads"),
		WebDir:        env("WEB_DIR", "web"),
		WorkerPath:    env("PHOTO_WORKER_PATH", "./photo/photo-worker"),
		TTL:           ttl,
	}
}
