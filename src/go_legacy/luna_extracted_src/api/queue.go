package api

import "sync"

type Queue[T any] struct {
    mu    sync.Mutex
    items []T
}

func (q *Queue[T]) Push(item T) {
    q.mu.Lock()
    q.items = append(q.items, item)
    q.mu.Unlock()
}

func (q *Queue[T]) Pop() (T, bool) {
    q.mu.Lock()
    defer q.mu.Unlock()
    var zero T
    if len(q.items) == 0 {
        return zero, false
    }
    item := q.items[0]
    q.items = q.items[1:]
    return item, true
}

func (q *Queue[T]) Len() int {
    q.mu.Lock()
    n := len(q.items)
    q.mu.Unlock()
    return n
}

func (q *Queue[T]) Clear() {
    q.mu.Lock()
    q.items = nil
    q.mu.Unlock()
}
