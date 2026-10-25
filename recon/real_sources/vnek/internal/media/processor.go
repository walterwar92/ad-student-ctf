package media

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"vnekontakta/internal/identity"
)

const MaxImageBytes int64 = 5 << 20

type Processor struct {
	Directory  string
	Executable string
}

func (p Processor) Process(ctx context.Context, src io.Reader, userUUID string) (string, error) {
	input, err := os.CreateTemp(p.Directory, "in-*")
	if err != nil {
		return "", err
	}
	name := input.Name()
	defer os.Remove(name)
	n, copyErr := io.Copy(input, io.LimitReader(src, MaxImageBytes+1))
	closeErr := input.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n > MaxImageBytes {
		return "", fmt.Errorf("image exceeds 5 MiB")
	}

	outName := identity.RandomToken() + ".png"
	output := filepath.Join(p.Directory, outName)
	workerCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(workerCtx, p.Executable, name, output, userUUID)
	if result, err := cmd.CombinedOutput(); err != nil {
		_ = os.Remove(output)
		log.Printf("photo-worker failed: %v: %s", err, result)
		return "", fmt.Errorf("image processing failed: %w", err)
	}
	return "/uploads/" + outName, nil
}

func (p Processor) Delete(photoURL string) {
	if photoURL != "" {
		_ = os.Remove(filepath.Join(p.Directory, filepath.Base(photoURL)))
	}
}
