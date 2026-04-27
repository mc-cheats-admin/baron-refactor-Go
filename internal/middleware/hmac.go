package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ─── HMAC Verification ───────────────────────────────────────────────────────

// AgentHMAC verifies X-Signature header: HMAC-SHA256(body, AGENT_SECRET).
// Set AGENT_SECRET env var on server. Same key must be baked into agent binary.
// If AGENT_SECRET is empty — middleware is skipped (dev mode).
func AgentHMAC() gin.HandlerFunc {
	secret := os.Getenv("AGENT_SECRET")
	if secret == "" {
		return func(c *gin.Context) { c.Next() }
	}
	key := []byte(secret)

	return func(c *gin.Context) {
		sig := c.GetHeader("X-Signature")
		if sig == "" {
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "missing signature"})
			c.Abort()
			return
		}

		// Read body for HMAC, then put it back for binding
		body, err := c.GetRawData()
		if err != nil || len(body) == 0 {
			// Empty body is OK for GET-style requests — just verify header token
			body = []byte{}
		}

		mac := hmac.New(sha256.New, key)
		mac.Write(body)
		expected := hex.EncodeToString(mac.Sum(nil))

		if !hmac.Equal([]byte(sig), []byte(expected)) {
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "invalid signature"})
			c.Abort()
			return
		}

		// Re-inject body so ShouldBindJSON still works downstream
		c.Request.Body = newReadCloser(body)
		c.Next()
	}
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

type rateBucket struct {
	count    int
	windowAt time.Time
	banned   bool
	bannedAt time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*rateBucket
	limit   int
	window  time.Duration
	banFor  time.Duration
}

func newRateLimiter(limit int, window, banFor time.Duration) *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*rateBucket),
		limit:   limit,
		window:  window,
		banFor:  banFor,
	}
	// Cleanup goroutine — evict old buckets every 5 minutes
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.mu.Lock()
			now := time.Now()
			for ip, b := range rl.buckets {
				if now.Sub(b.windowAt) > window*2 && (!b.banned || now.Sub(b.bannedAt) > banFor) {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &rateBucket{count: 1, windowAt: now}
		return true
	}

	// Check ban
	if b.banned {
		if now.Sub(b.bannedAt) < rl.banFor {
			return false
		}
		b.banned = false
		b.count = 1
		b.windowAt = now
		return true
	}

	// Slide window
	if now.Sub(b.windowAt) > rl.window {
		b.count = 1
		b.windowAt = now
		return true
	}

	b.count++
	if b.count > rl.limit {
		b.banned = true
		b.bannedAt = now
		return false
	}
	return true
}

// beaconLimiter: 120 req/min per IP
var beaconLimiter = newRateLimiter(120, time.Minute, 5*time.Minute)

// registerLimiter: 10 req/min per IP
var registerLimiter = newRateLimiter(10, time.Minute, 10*time.Minute)

// RateLimit returns a gin middleware for a given limiter
func RateLimit(rl *rateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{"ok": false, "error": "rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// Exported limiters for use in main.go
func BeaconRateLimit() gin.HandlerFunc   { return RateLimit(beaconLimiter) }
func RegisterRateLimit() gin.HandlerFunc { return RateLimit(registerLimiter) }
