package accesscontrol

import (
	"sync"
	"time"
)

type slidingWindow struct {
	mu      sync.Mutex
	buckets map[string][]time.Time
}

func newSlidingWindow() *slidingWindow {
	return &slidingWindow{buckets: make(map[string][]time.Time)}
}

func (w *slidingWindow) record(key string, now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buckets[key] = append(w.buckets[key], now)
}

func (w *slidingWindow) count(key string, window time.Duration) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := time.Now().Add(-window)
	stamps := w.buckets[key]
	start := 0
	for start < len(stamps) && stamps[start].Before(cutoff) {
		start++
	}
	if start > 0 {
		w.buckets[key] = stamps[start:]
	}
	return len(w.buckets[key])
}

func (w *slidingWindow) purgeOlderThan(maxAge time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for key, stamps := range w.buckets {
		start := 0
		for start < len(stamps) && stamps[start].Before(cutoff) {
			start++
		}
		if start >= len(stamps) {
			delete(w.buckets, key)
		} else if start > 0 {
			w.buckets[key] = stamps[start:]
		}
	}
}
