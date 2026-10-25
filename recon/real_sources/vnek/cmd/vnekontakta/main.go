package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"vnekontakta/internal/app"
	"vnekontakta/internal/config"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, config.Load()); err != nil {
		log.Fatal(err)
	}
}
