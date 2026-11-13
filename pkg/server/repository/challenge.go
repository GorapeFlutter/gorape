package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

var ErrChallengeInvalid = errors.New("challenge missing, expired, or already used")

type Challenge struct {
	ID        string    `json:"id"`
	Value     []byte    `json:"value"`
	ProjectID uuid.UUID `json:"project_id"`
	Subject   string    `json:"subject"`
	Purpose   string    `json:"purpose"`
	DeviceID  uuid.UUID `json:"device_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}
type ChallengeStore interface {
	Create(context.Context, uuid.UUID, string, string, uuid.UUID) (Challenge, error)
	Consume(context.Context, string) (Challenge, error)
}
type RedisChallengeStore struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

func NewRedisChallengeStore(c *redis.Client, prefix string, ttl time.Duration) *RedisChallengeStore {
	return &RedisChallengeStore{client: c, prefix: prefix, ttl: ttl}
}
func (rcvr *RedisChallengeStore) Create(ctx context.Context, p uuid.UUID, sub, purpose string, d uuid.UUID) (Challenge, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return Challenge{}, e
	}
	v := Challenge{ID: uuid.NewString(), Value: b, ProjectID: p, Subject: sub, Purpose: purpose, DeviceID: d, ExpiresAt: time.Now().UTC().Add(rcvr.ttl)}
	raw, e := json.Marshal(v)
	if e != nil {
		return v, e
	}
	e = rcvr.client.Set(ctx, rcvr.prefix+v.ID, raw, rcvr.ttl).Err()
	return v, e
}

var consumeScript = redis.NewScript(`local v=redis.call('GET',KEYS[1]); if not v then return nil end; redis.call('DEL',KEYS[1]); return v`)

func (rcvr *RedisChallengeStore) Consume(ctx context.Context, id string) (Challenge, error) {
	result, e := consumeScript.Run(ctx, rcvr.client, []string{rcvr.prefix + id}).Result()
	if e == redis.Nil {
		return Challenge{}, ErrChallengeInvalid
	}
	if e != nil {
		return Challenge{}, e
	}
	raw, ok := result.(string)
	if !ok {
		return Challenge{}, ErrChallengeInvalid
	}
	var v Challenge
	if json.Unmarshal([]byte(raw), &v) != nil || time.Now().After(v.ExpiresAt) {
		return Challenge{}, ErrChallengeInvalid
	}
	return v, nil
}
func EncodeChallenge(v Challenge) string { return base64.RawURLEncoding.EncodeToString(v.Value) }

type MemoryChallengeStore struct {
	mu    sync.Mutex
	ttl   time.Duration
	items map[string]Challenge
}

func NewMemoryChallengeStore(ttl time.Duration) *MemoryChallengeStore {
	return &MemoryChallengeStore{ttl: ttl, items: map[string]Challenge{}}
}
func (rcvr *MemoryChallengeStore) Create(_ context.Context, p uuid.UUID, sub, purpose string, d uuid.UUID) (Challenge, error) {
	rcvr.mu.Lock()
	defer rcvr.mu.Unlock()
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return Challenge{}, e
	}
	v := Challenge{ID: uuid.NewString(), Value: b, ProjectID: p, Subject: sub, Purpose: purpose, DeviceID: d, ExpiresAt: time.Now().UTC().Add(rcvr.ttl)}
	rcvr.items[v.ID] = v
	return v, nil
}
func (rcvr *MemoryChallengeStore) Consume(_ context.Context, id string) (Challenge, error) {
	rcvr.mu.Lock()
	defer rcvr.mu.Unlock()
	v, ok := rcvr.items[id]
	delete(rcvr.items, id)
	if !ok || time.Now().After(v.ExpiresAt) {
		return Challenge{}, ErrChallengeInvalid
	}
	return v, nil
}
