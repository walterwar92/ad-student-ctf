package app

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"vnekontakta/internal/config"
	"vnekontakta/internal/httpapi"
	"vnekontakta/internal/identity"
	"vnekontakta/internal/media"
	"vnekontakta/internal/repository"
	"vnekontakta/internal/social"
)

func Build(ctx context.Context, cfg config.Config) (http.Handler, *social.Service, error) {
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		return nil, nil, err
	}
	db, err := repository.Open(ctx, cfg.DatabaseURL, cfg.MigrationPath)
	if err != nil {
		return nil, nil, err
	}
	seed, err := db.UUIDSeed(ctx)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	ids, err := identity.New(seed)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	s := &social.Service{Store: db, IDs: ids, Images: media.Processor{Directory: cfg.UploadDir, Executable: cfg.WorkerPath}}
	return httpapi.New(s, cfg.WebDir, cfg.UploadDir), s, nil
}

func Run(ctx context.Context, cfg config.Config) error {
	handler, s, err := Build(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.Store.Close()
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if err := s.Cleanup(cleanupCtx, cfg.TTL); err != nil {
					log.Printf("cleanup: %v", err)
				}
				cancel()
			}
		}
	}()
	server := &http.Server{Addr: ":" + cfg.Port, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 35 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("ВнеКонтакта listening on :%s", cfg.Port)
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
