package main

import (
	"fmt"
	"sync"
)

type inMemoryStore struct {
	sync.RWMutex
	store map[string]string
}

func newInMemoryStore() *inMemoryStore {
	return &inMemoryStore{store: make(map[string]string, 0)}
}

func (s *inMemoryStore) Get(key string) (string, error) {
	s.RLock()
	defer s.RUnlock()

	val, ok := s.store[key]
	if !ok {
		return "", fmt.Errorf("no entry found for the provided key %s", key)
	}

	return val, nil
}

func (s *inMemoryStore) Set(key, val string) {
	s.Lock()
	defer s.Unlock()

	s.store[key] = val
}

func (s *inMemoryStore) Remove(key string) {
	s.Lock()
	defer s.Unlock()

	delete(s.store, key)
}
