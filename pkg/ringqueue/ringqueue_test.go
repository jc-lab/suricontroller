package ringqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func strQueue(capacity int64) *Queue[string] {
	return New(capacity, func(s string) int { return len(s) })
}

func TestDropOldest(t *testing.T) {
	q := strQueue(10)
	q.Push("aaaa")
	q.Push("bbbb")
	if d := q.Push("cccc"); d != 1 {
		t.Fatalf("dropped = %d", d)
	}
	got, _ := q.PopBatch(context.Background(), 10, 100)
	if len(got) != 2 || got[0] != "bbbb" || got[1] != "cccc" {
		t.Fatalf("got %v", got)
	}
	if d := q.Push("this item is larger than capacity"); d != 1 {
		t.Fatal("oversized item not dropped")
	}
	st := q.Stats()
	if st.Dropped != 2 || st.Len != 0 || st.Bytes != 0 || st.Pushed != 4 || st.Popped != 2 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestBatchLimits(t *testing.T) {
	q := strQueue(100)
	for _, s := range []string{"aaaaa", "bbbbb", "ccccc", "ddddd"} {
		q.Push(s)
	}
	got, _ := q.PopBatch(context.Background(), 3, 12)
	if len(got) != 2 {
		t.Fatalf("byte limit: got %v", got)
	}
	got, _ = q.PopBatch(context.Background(), 1, 100)
	if len(got) != 1 || got[0] != "ccccc" {
		t.Fatalf("item limit: got %v", got)
	}
	// A single item larger than maxBytes is still returned.
	q.Push("0123456789")
	got, _ = q.PopBatch(context.Background(), 10, 3)
	if len(got) != 1 || got[0] != "ddddd" {
		t.Fatalf("got %v", got)
	}
}

func TestBlockingPopAndClose(t *testing.T) {
	q := strQueue(100)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, err := q.PopBatch(context.Background(), 10, 100)
		if err != nil || len(got) != 1 || got[0] != "x" {
			t.Errorf("got %v %v", got, err)
		}
	}()
	time.Sleep(10 * time.Millisecond)
	q.Push("x")
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := q.PopBatch(ctx, 1, 1); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	q.Push("y")
	q.Close()
	if got, err := q.PopBatch(context.Background(), 10, 100); err != nil || got[0] != "y" {
		t.Fatal("items queued before Close must drain")
	}
	if _, err := q.PopBatch(context.Background(), 10, 100); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestSetCapacityShrinks(t *testing.T) {
	q := strQueue(100)
	for range 10 {
		q.Push("0123456789")
	}
	q.SetCapacity(25)
	if st := q.Stats(); st.Len != 2 || st.Bytes != 20 || st.Dropped != 8 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestOnDrop(t *testing.T) {
	q := New[int](3, func(int) int { return 1 })
	var dropped []int
	q.SetOnDrop(func(v int) { dropped = append(dropped, v) })
	for i := 1; i <= 5; i++ {
		q.Push(i)
	}
	q.SetCapacity(1)
	if fmt.Sprint(dropped) != "[1 2 3 4]" {
		t.Fatalf("dropped = %v", dropped)
	}
}
