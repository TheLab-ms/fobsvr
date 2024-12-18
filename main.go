package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
)

func main() {
	var (
		callbackURL     = flag.String("callback-url", "", "URL at which Keycloak can reach this service")
		resync          = flag.Duration("resync-interval", time.Hour, "How often to resync if no webhook has been received")
		keycloakURL     = flag.String("keycloak-url", "", "Base URL of Keycloak")
		keycloakGroupID = flag.String("keycloak-group-id", "", "UUID of the trusted Keycloak group")
	)
	flag.Parse()

	k := newKeycloak(*keycloakURL, *keycloakGroupID)
	if *callbackURL != "" {
		err := k.EnsureWebhook(context.Background(), *callbackURL)
		if err != nil {
			panic(err)
		}
	}

	router := httprouter.New()
	cache := newCache(k)
	router.GET("/healthz", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if c, _ := cache.Load(); c == nil {
			w.WriteHeader(500) // wait for cache to warm before accepting requests
			return
		}
		w.WriteHeader(204)
	})

	router.GET("/v1/fobs", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if wait := r.URL.Query().Get("wait"); wait != "" {
			waitDuration, err := time.ParseDuration(wait)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			cache.Wait(waitDuration)
		}

		users, hash := cache.Load()
		if hash != "" && hash == r.Header.Get("If-None-Match") {
			w.WriteHeader(304)
			return
		}

		w.Header().Set("ETag", hash)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&users)
	})

	router.POST("/v1/events", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		e := &Event{}
		err := json.NewDecoder(r.Body).Decode(e)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// TODO: Actually store these somewhere
		slog.Info("received event", "timestamp", e.Timestamp, "personID", e.PersonID, "fobID", e.FobID, "qrID", e.QRID, "authorized", e.Authorized)
	})

	refresh := make(chan struct{}, 1)
	refresh <- struct{}{}
	router.POST("/webhook", func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		slog.Info("received webhook")
		select {
		case refresh <- struct{}{}:
		default:
		}
	})

	// Sync periodically
	go func() {
		for range time.NewTicker(*resync).C {
			select {
			case refresh <- struct{}{}:
			default:
			}
		}
	}()

	// Keycloak loop
	go func() {
		var lastRetry time.Duration
		for range refresh {
			err := cache.Fill()
			if err != nil {
				slog.Error("unable to fill cache", "error", err)
			} else {
				lastRetry = 0
				continue
			}

			if lastRetry == 0 {
				lastRetry = time.Millisecond * 250
			}
			lastRetry += lastRetry / 2
			if lastRetry > *resync {
				lastRetry = *resync
			}
			time.Sleep(lastRetry)
		}
	}()

	panic(http.ListenAndServe(":8080", router))
}

type Event struct {
	Timestamp  int64  `json:"timestamp"`
	PersonID   string `json:"personID"`
	FobID      int64  `json:"fobID"`
	QRID       int64  `json:"qrID"`
	Authorized bool   `json:"authorized"`
}
