package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sort"
	"sync"
	"time"
)

type cache struct {
	keycloak *keycloak

	lock     sync.Mutex
	state    []*AccessUser
	hash     string
	watchers map[chan struct{}]struct{}
}

func newCache(k *keycloak) *cache {
	return &cache{keycloak: k, watchers: map[chan struct{}]struct{}{}}
}

func (c *cache) Fill() error {
	ctx, done := context.WithTimeout(context.Background(), time.Minute)
	defer done()

	users, err := c.keycloak.ListUsers(ctx)
	if err != nil {
		return err
	}

	sort.Slice(users, func(i, j int) bool { return users[i].FobID < users[j].FobID })
	hash := calculateUsersHash(users)

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.hash == hash {
		slog.Info("cache was filled but nothing changed")
		return nil // nothing has changed
	}
	c.state = users
	c.hash = hash

	for ch := range c.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}

	slog.Info("filled cache")
	return nil
}

func (c *cache) Load() ([]*AccessUser, string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.state, c.hash
}

func (c *cache) Wait(period time.Duration) {
	ch := make(chan struct{}, 1)
	c.lock.Lock()
	c.watchers[ch] = struct{}{}
	c.lock.Unlock()

	t := time.NewTimer(period)
	defer t.Stop()

	select {
	case <-ch:
	case <-t.C:
	}

	c.lock.Lock()
	delete(c.watchers, ch)
	c.lock.Unlock()
	close(ch)
}

func calculateUsersHash(users []*AccessUser) string {
	js, _ := json.Marshal(&users)
	hash := sha256.Sum256(js)
	return hex.EncodeToString(hash[:])
}
