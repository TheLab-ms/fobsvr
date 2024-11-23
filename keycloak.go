package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

type keycloak struct {
	client                  *gocloak.GoCloak
	realm, baseURL, groupID string

	// use ensureToken to access these
	tokenLock      sync.Mutex
	token          *gocloak.JWT
	tokenFetchTime time.Time
}

func newKeycloak(url, groupID string) *keycloak {
	return &keycloak{client: gocloak.NewClient(url), realm: "master", baseURL: url, groupID: groupID}
}

func (k *keycloak) ListUsers(ctx context.Context) ([]*AccessUser, error) {
	token, err := k.ensureToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting token: %w", err)
	}

	var (
		max   = 50
		first = 0
		all   = []*AccessUser{}
	)
	for {
		params, err := gocloak.GetQueryParams(gocloak.GetUsersParams{
			Max:   &max,
			First: &first,
		})
		if err != nil {
			return nil, err
		}

		// Unfortunately the keycloak client doesn't support the group membership endpoint.
		// We reuse the client's transport here while specifying our own URL.
		var users []*gocloak.User
		_, err = k.client.GetRequestWithBearerAuth(ctx, token.AccessToken).
			SetResult(&users).
			SetQueryParams(params).
			Get(fmt.Sprintf("%s/admin/realms/%s/groups/%s/members", k.baseURL, k.realm, k.groupID))
		if err != nil {
			return nil, err
		}
		if len(users) == 0 {
			break
		}
		first += len(users)

		for _, user := range users {
			u := newAccessUser(user)
			if u == nil {
				continue // invalid user (should be impossible)
			}
			all = append(all, u)
		}
	}

	return all, nil
}

func (k *keycloak) EnsureWebhook(ctx context.Context, callbackURL string) error {
	hooks, err := k.ListWebhooks(ctx)
	if err != nil {
		return fmt.Errorf("listing: %w", err)
	}

	url := fmt.Sprintf("%s/webhook", callbackURL)
	for _, hook := range hooks {
		if hook.URL == url {
			return nil // already exists
		}
	}

	return k.CreateWebhook(ctx, &Webhook{
		Enabled:    true,
		URL:        url,
		EventTypes: []string{"admin.*"},
	})
}

func (k *keycloak) ListWebhooks(ctx context.Context) ([]*Webhook, error) {
	token, err := k.ensureToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting token: %w", err)
	}

	webhooks := []*Webhook{}
	_, err = k.client.GetRequestWithBearerAuth(ctx, token.AccessToken).
		SetResult(&webhooks).
		Get(fmt.Sprintf("%s/realms/%s/webhooks", k.baseURL, k.realm))
	if err != nil {
		return nil, err
	}

	return webhooks, nil
}

func (k *keycloak) CreateWebhook(ctx context.Context, webhook *Webhook) error {
	token, err := k.ensureToken(ctx)
	if err != nil {
		return fmt.Errorf("getting token: %w", err)
	}

	_, err = k.client.GetRequestWithBearerAuth(ctx, token.AccessToken).
		SetBody(webhook).
		Post(fmt.Sprintf("%s/realms/%s/webhooks", k.baseURL, k.realm))
	if err != nil {
		return err
	}

	return nil
}

// For whatever reason the Keycloak client doesn't support token rotation
func (k *keycloak) ensureToken(ctx context.Context) (*gocloak.JWT, error) {
	k.tokenLock.Lock()
	defer k.tokenLock.Unlock()

	if k.token != nil && time.Since(k.tokenFetchTime) < (time.Duration(k.token.ExpiresIn)*time.Second)/2 {
		return k.token, nil
	}

	clientID, err := os.ReadFile("/var/lib/keycloak/client-id")
	if err != nil {
		return nil, fmt.Errorf("reading client id: %w", err)
	}
	clientSecret, err := os.ReadFile("/var/lib/keycloak/client-secret")
	if err != nil {
		return nil, fmt.Errorf("reading client secret: %w", err)
	}

	token, err := k.client.LoginClient(ctx, string(clientID), string(clientSecret), k.realm)
	if err != nil {
		return nil, err
	}
	k.token = token
	k.tokenFetchTime = time.Now()

	log.Printf("fetched new auth token from keycloak - will expire in %d seconds", k.token.ExpiresIn)
	return k.token, nil
}

type AccessUser struct {
	UserID string `json:"userID"`
	FobID  int    `json:"fobID,omitempty"`
	QRID   int    `json:"qrID,omitempty"`
	TTL    int64  `json:"ttl"`
}

func newAccessUser(kcuser *gocloak.User) *AccessUser {
	if kcuser.ID == nil || kcuser.Attributes == nil {
		return nil
	}

	attr := *kcuser.Attributes
	fobID, _ := strconv.Atoi(firstElOrZeroVal(attr["keyfobID"]))
	qrID, _ := strconv.Atoi(firstElOrZeroVal(attr["qrID"]))
	if fobID == 0 && qrID == 0 {
		return nil
	}
	if firstElOrZeroVal(attr["buildingAccessApprover"]) == "" {
		return nil // no access for accounts that haven't explicitly been granted building access
	}

	return &AccessUser{
		UserID: *kcuser.ID,
		FobID:  fobID,
		QRID:   qrID,
		TTL:    (time.Hour * 24).Milliseconds(), // TODO: Load from keycloak
	}
}

type Webhook struct {
	ID         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	URL        string   `json:"url"`
	EventTypes []string `json:"eventTypes"`
}

func firstElOrZeroVal[T any](slice []T) (val T) {
	if len(slice) == 0 {
		return val
	}
	return slice[0]
}
