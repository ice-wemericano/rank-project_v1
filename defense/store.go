package defense

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ProofState 는 열람증명 토큰의 서버측 상태다. heartbeat 로 실제 체류시간을 누적한다.
type ProofState struct {
	PostID   int       `json:"post_id"`
	IP       string    `json:"ip"`
	IssuedAt time.Time `json:"issued_at"`
	LastBeat time.Time `json:"last_beat"`
	ActiveMS int64     `json:"active_ms"` // 누적된 실제 체류시간(ms)
}

// Store 는 방어 상태(중복/속도/열람증명) 저장소다.
// 메모리 구현과 Redis 구현이 있으며, Redis 를 쓰면 재시작·다중서버에서 상태가 유지된다.
type Store interface {
	// FirstWithin 은 식별자를 window 동안 "본 적 있음"으로 표시하고, 이번이 처음이면 true.
	FirstWithin(key string, window time.Duration) (bool, error)
	// Incr 은 식별자의 window 내 카운터를 1 증가시키고 현재 값을 돌려준다(속도제한용).
	Incr(key string, window time.Duration) (int, error)
	// PutProof / GetProof / ConsumeProof 는 열람증명 상태를 저장/조회/일회성소비 한다.
	PutProof(nonce string, p ProofState, ttl time.Duration) error
	GetProof(nonce string) (*ProofState, error)
	ConsumeProof(nonce string) (*ProofState, error) // 원자적 get+delete (재사용 차단)
	// Flush 는 모든 방어 상태를 초기화한다(reset 용). 레벨 설정은 지우지 않는다.
	Flush() error
	// SaveLevels / LoadLevels 는 방어 레벨 설정을 보존한다(재시작·재배포 후에도 유지).
	SaveLevels(b []byte) error
	LoadLevels() ([]byte, error)
}

// ---------- 메모리 구현 ----------

type MemoryStore struct {
	mu      sync.Mutex
	lastHit map[string]time.Time
	hits    map[string][]time.Time
	proofs  map[string]*ProofState
	levels  []byte
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		lastHit: map[string]time.Time{},
		hits:    map[string][]time.Time{},
		proofs:  map[string]*ProofState{},
	}
}

func (m *MemoryStore) FirstWithin(key string, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if t, ok := m.lastHit[key]; ok && now.Sub(t) < window {
		return false, nil
	}
	m.lastHit[key] = now
	return true, nil
}

func (m *MemoryStore) Incr(key string, window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	cut := now.Add(-window)
	kept := m.hits[key][:0]
	for _, t := range m.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	m.hits[key] = kept
	return len(kept), nil
}

func (m *MemoryStore) PutProof(nonce string, p ProofState, ttl time.Duration) error {
	m.mu.Lock()
	cp := p
	m.proofs[nonce] = &cp
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) GetProof(nonce string) (*ProofState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proofs[nonce]
	if !ok {
		return nil, nil
	}
	cp := *p
	return &cp, nil
}

func (m *MemoryStore) ConsumeProof(nonce string) (*ProofState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.proofs[nonce]
	if !ok {
		return nil, nil
	}
	delete(m.proofs, nonce)
	return p, nil
}

func (m *MemoryStore) Flush() error {
	m.mu.Lock()
	m.lastHit = map[string]time.Time{}
	m.hits = map[string][]time.Time{}
	m.proofs = map[string]*ProofState{}
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) SaveLevels(b []byte) error {
	m.mu.Lock()
	m.levels = append([]byte(nil), b...)
	m.mu.Unlock()
	return nil
}

func (m *MemoryStore) LoadLevels() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.levels, nil
}

// ---------- Redis 구현 ----------

type RedisStore struct {
	c *redis.Client
}

func NewRedisStore(addr, password string, db int) (*RedisStore, error) {
	c := redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})
	ctx, cancel := ctxTimeout()
	defer cancel()
	if err := c.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &RedisStore{c: c}, nil
}

func ctxTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 3*time.Second)
}

func (r *RedisStore) FirstWithin(key string, window time.Duration) (bool, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	// SET NX: 처음 보는 식별자면 true (window 동안 유지).
	return r.c.SetNX(ctx, "dedup:"+key, 1, window).Result()
}

func (r *RedisStore) Incr(key string, window time.Duration) (int, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	k := "rate:" + key
	n, err := r.c.Incr(ctx, k).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 {
		r.c.Expire(ctx, k, window)
	}
	return int(n), nil
}

func (r *RedisStore) PutProof(nonce string, p ProofState, ttl time.Duration) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return r.c.Set(ctx, "proof:"+nonce, b, ttl).Err()
}

func (r *RedisStore) GetProof(nonce string) (*ProofState, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	b, err := r.c.Get(ctx, "proof:"+nonce).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p ProofState
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *RedisStore) ConsumeProof(nonce string) (*ProofState, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	// GETDEL: 원자적으로 읽고 삭제 → 재사용 차단.
	b, err := r.c.GetDel(ctx, "proof:"+nonce).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p ProofState
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (r *RedisStore) Flush() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, prefix := range []string{"dedup:*", "rate:*", "proof:*"} {
		iter := r.c.Scan(ctx, 0, prefix, 100).Iterator()
		for iter.Next(ctx) {
			r.c.Del(ctx, iter.Val())
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	return nil
}

const levelsKey = "config:levels" // Flush 대상(dedup/rate/proof) 아님

func (r *RedisStore) SaveLevels(b []byte) error {
	ctx, cancel := ctxTimeout()
	defer cancel()
	return r.c.Set(ctx, levelsKey, b, 0).Err()
}

func (r *RedisStore) LoadLevels() ([]byte, error) {
	ctx, cancel := ctxTimeout()
	defer cancel()
	b, err := r.c.Get(ctx, levelsKey).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return b, err
}
