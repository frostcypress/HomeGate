package scheduler

import "testing"

func TestQueueDeduplicatesSameKind(t *testing.T) {
	q := New(4)
	for i := 0; i < 100; i++ {
		if !q.Submit(EventWANChanged) {
			t.Fatalf("Submit failed at %d", i)
		}
	}
	if got := q.Len(); got != 1 {
		t.Fatalf("Len=%d want 1", got)
	}
	ev, ok := q.Next()
	if !ok || ev.Kind != EventWANChanged {
		t.Fatalf("Next=%+v ok=%v", ev, ok)
	}
	if _, ok := q.Next(); ok {
		t.Fatal("duplicate event was not collapsed")
	}
}

func TestQueueBoundedForDistinctKinds(t *testing.T) {
	q := New(2)
	if !q.Submit(EventConfigChanged) || !q.Submit(EventWANChanged) {
		t.Fatal("first two events should fit")
	}
	if q.Submit(EventDDNSTimer) {
		t.Fatal("third distinct event should be rejected by bound")
	}
	if got := q.Len(); got != 2 {
		t.Fatalf("Len=%d want 2", got)
	}
}

func TestQueuePreservesDistinctOrder(t *testing.T) {
	q := New(4)
	q.Submit(EventDDNSTimer)
	q.Submit(EventConfigChanged)
	q.Submit(EventDDNSTimer)
	first, _ := q.Next()
	second, _ := q.Next()
	if first.Kind != EventDDNSTimer || second.Kind != EventConfigChanged {
		t.Fatalf("order=%s,%s", first.Kind, second.Kind)
	}
}

func TestQueueDeduplicatesTimerKindsIndependently(t *testing.T) {
	q := New(8)
	kinds := []Kind{EventDDNSTimer, EventACMETimer, EventAccessTimer}
	for i := 0; i < 100; i++ {
		for _, kind := range kinds {
			if !q.Submit(kind) {
				t.Fatalf("Submit(%s) failed at %d", kind, i)
			}
		}
	}
	if got := q.Len(); got != len(kinds) {
		t.Fatalf("Len=%d want %d", got, len(kinds))
	}
	for _, want := range kinds {
		ev, ok := q.Next()
		if !ok || ev.Kind != want {
			t.Fatalf("Next=%+v ok=%v want=%s", ev, ok, want)
		}
	}
	if _, ok := q.Next(); ok {
		t.Fatal("timer duplicates were not collapsed")
	}
}
