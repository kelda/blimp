package tracker

import (
	"sync"
)

type VolumeTracker struct {
	// Namespace to a map of file path to expected hash.
	hashes map[string]map[string]string
	lock   sync.Mutex
}

func NewVolumeTracker() *VolumeTracker {
	return &VolumeTracker{hashes: map[string]map[string]string{}}
}

func (t *VolumeTracker) Set(namespace string, hashes map[string]string) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.hashes[namespace] = hashes
}

func (t *VolumeTracker) Get(namespace, path string) (string, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	path, ok := t.hashes[namespace][path]
	return path, ok
}
