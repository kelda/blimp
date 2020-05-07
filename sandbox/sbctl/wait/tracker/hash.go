package tracker

import (
	"sync"
)

type VolumeTracker struct {
	hashes map[string]string
	lock   sync.Mutex
}

func NewVolumeTracker() *VolumeTracker {
	return &VolumeTracker{hashes: map[string]string{}}
}

func (t *VolumeTracker) Set(hashes map[string]string) {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.hashes = hashes
}

func (t *VolumeTracker) Get(path string) (string, bool) {
	t.lock.Lock()
	defer t.lock.Unlock()
	path, ok := t.hashes[path]
	return path, ok
}
