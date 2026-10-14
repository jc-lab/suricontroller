// Package ringqueue implements a byte-bounded FIFO queue that never blocks
// producers: when it is full, the oldest items are dropped.
package ringqueue

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by Pop after Close once the queue is drained.
var ErrClosed = errors.New("ringqueue: closed")

// Stats is a snapshot of queue counters.
type Stats struct {
	Len      int
	Bytes    int64
	Capacity int64
	Pushed   uint64
	Popped   uint64
	Dropped  uint64
}

type entry[T any] struct {
	v    T
	size int64
}

// Queue is a FIFO bounded by the total size of its items.
type Queue[T any] struct {
	mu       sync.Mutex
	items    []entry[T]
	head     int
	bytes    int64
	capacity int64
	sizeOf   func(T) int
	notify   chan struct{}
	closed   bool
	stats    Stats
}

// New creates a queue holding at most capacity bytes, as measured by sizeOf.
func New[T any](capacity int64, sizeOf func(T) int) *Queue[T] {
	return &Queue[T]{capacity: capacity, sizeOf: sizeOf, notify: make(chan struct{})}
}

// Push appends v, dropping the oldest items as needed. An item larger than
// the capacity is dropped itself. It returns the number of dropped items.
func (q *Queue[T]) Push(v T) int {
	size := int64(q.sizeOf(v))
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		q.stats.Dropped++
		return 1
	}
	q.stats.Pushed++
	if size > q.capacity {
		q.stats.Dropped++
		return 1
	}
	dropped := q.evict(q.capacity - size)
	q.items = append(q.items, entry[T]{v: v, size: size})
	q.bytes += size
	q.wake()
	return dropped
}

// evict drops oldest items until bytes <= limit. Callers hold mu.
func (q *Queue[T]) evict(limit int64) int {
	n := 0
	for q.bytes > limit && q.head < len(q.items) {
		q.bytes -= q.items[q.head].size
		var zero entry[T]
		q.items[q.head] = zero
		q.head++
		n++
	}
	q.stats.Dropped += uint64(n)
	q.compact()
	return n
}

func (q *Queue[T]) compact() {
	if q.head > 0 && q.head*2 >= len(q.items) {
		n := copy(q.items, q.items[q.head:])
		clear(q.items[n:])
		q.items = q.items[:n]
		q.head = 0
	}
}

func (q *Queue[T]) wake() {
	close(q.notify)
	q.notify = make(chan struct{})
}

// SetCapacity changes the capacity, dropping oldest items if needed.
func (q *Queue[T]) SetCapacity(capacity int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.capacity = capacity
	q.evict(capacity)
}

// PopBatch waits until at least one item is available and returns up to
// maxItems items whose total size does not exceed maxBytes (at least one
// item is always returned). It returns ErrClosed after Close once drained.
func (q *Queue[T]) PopBatch(ctx context.Context, maxItems int, maxBytes int64) ([]T, error) {
	for {
		q.mu.Lock()
		if q.head < len(q.items) {
			var out []T
			var total int64
			for q.head < len(q.items) && len(out) < maxItems {
				e := q.items[q.head]
				if len(out) > 0 && total+e.size > maxBytes {
					break
				}
				out = append(out, e.v)
				total += e.size
				var zero entry[T]
				q.items[q.head] = zero
				q.head++
			}
			q.bytes -= total
			q.stats.Popped += uint64(len(out))
			q.compact()
			q.mu.Unlock()
			return out, nil
		}
		if q.closed {
			q.mu.Unlock()
			return nil, ErrClosed
		}
		ch := q.notify
		q.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Close stops accepting items and wakes waiting consumers.
func (q *Queue[T]) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.closed {
		q.closed = true
		q.wake()
	}
}

// Stats returns a snapshot of the counters.
func (q *Queue[T]) Stats() Stats {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.stats
	s.Len = len(q.items) - q.head
	s.Bytes = q.bytes
	s.Capacity = q.capacity
	return s
}
