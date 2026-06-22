package authz

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

func NewFromFile(
	ctx context.Context,
	path string,
	onReloadError func(error),
) (*Authorizer, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve policy path: %w", err)
	}

	source, err := os.ReadFile(absolutePath)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	authorizer, err := New(ctx, string(source))
	if err != nil {
		return nil, err
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create policy watcher: %w", err)
	}
	if err := watcher.Add(filepath.Dir(absolutePath)); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("watch policy directory: %w", err)
	}

	go authorizer.watchFile(ctx, watcher, absolutePath, onReloadError)

	return authorizer, nil
}

func (a *Authorizer) watchFile(
	ctx context.Context,
	watcher *fsnotify.Watcher,
	path string,
	onReloadError func(error),
) {
	defer watcher.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			reportReloadError(onReloadError, fmt.Errorf("watch policy: %w", err))
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if !sameFile(event.Name, path) || event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}

			source, err := os.ReadFile(path)
			if err != nil {
				reportReloadError(onReloadError, fmt.Errorf("read changed policy: %w", err))
				continue
			}
			if err := a.Reload(ctx, string(source)); err != nil {
				reportReloadError(onReloadError, fmt.Errorf("reload changed policy: %w", err))
			}
		}
	}
}

func sameFile(left, right string) bool {
	leftPath, err := filepath.Abs(left)
	if err != nil {
		return false
	}

	return filepath.Clean(leftPath) == filepath.Clean(right)
}

func reportReloadError(report func(error), err error) {
	if report != nil {
		report(err)
	}
}
