package scheduler

import "sync"

// Kind identifies a daemon control-plane event. The scheduler deliberately
// knows nothing about HomeGate business modules beyond these stable event keys.
type Kind string

const (
	EventStartup       Kind = "startup"
	EventConfigChanged Kind = "config_changed"
	EventWANChanged    Kind = "wan_changed"
	EventDDNSTimer     Kind = "ddns_timer"
	EventACMETimer     Kind = "acme_timer"
	EventAccessTimer   Kind = "access_timer"
	EventFirewallRetry Kind = "firewall_retry"
	EventProxyRetry    Kind = "proxy_retry"
	EventDDNSRetry     Kind = "ddns_retry"
	EventACMERetry     Kind = "acme_retry"
	EventAccessRetry   Kind = "access_retry"
)

type Event struct {
	Kind Kind
}

// Queue is a bounded, deduplicating event queue. At most one pending event of
// each Kind can exist. Repeated hotplug/signals/timer ticks collapse instead of
// growing memory or creating an event storm.
type Queue struct {
	mu       sync.Mutex
	capacity int
	pending  map[Kind]bool
	order    []Kind
	notify   chan struct{}
}

func New(capacity int) *Queue {
	if capacity < 1 {
		capacity = 1
	}
	return &Queue{
		capacity: capacity,
		pending:  make(map[Kind]bool, capacity),
		notify:   make(chan struct{}, 1),
	}
}

// Submit never blocks. It returns true when the event is queued or already
// pending, and false only when a distinct-key event cannot fit in the bound.
func (q *Queue) Submit(kind Kind) bool {
	if kind == "" {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.pending[kind] {
		q.signalLocked()
		return true
	}
	if len(q.order) >= q.capacity {
		return false
	}
	q.pending[kind] = true
	q.order = append(q.order, kind)
	q.signalLocked()
	return true
}

func (q *Queue) C() <-chan struct{} { return q.notify }

// Next returns one pending event. Consumers woken by C should drain Next until
// it returns false; Submit is responsible for notifications, so draining does
// not create spurious wakeups after the queue becomes empty.
func (q *Queue) Next() (Event, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.order) == 0 {
		return Event{}, false
	}
	kind := q.order[0]
	copy(q.order, q.order[1:])
	q.order = q.order[:len(q.order)-1]
	delete(q.pending, kind)
	return Event{Kind: kind}, true
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.order)
}

func (q *Queue) signalLocked() {
	select {
	case q.notify <- struct{}{}:
	default:
	}
}
