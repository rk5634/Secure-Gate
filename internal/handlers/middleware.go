package handlers

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const rateLimitLuaScript = `
local key = KEYS[1]
local max_tokens = tonumber(ARGV[1])
local refill_interval = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local bucket = redis.call("HMGET", key, "tokens", "timestamp")
local tokens = tonumber(bucket[1])
local last_refill = tonumber(bucket[2])

if tokens == nil then
    tokens = max_tokens
    last_refill = now
end

if last_refill == nil then
    last_refill = now
end

local delta = math.max(0, now - last_refill)
local refill = math.floor(delta / refill_interval)
if refill > 0 then
    tokens = math.min(max_tokens, tokens + refill)
    last_refill = last_refill + refill * refill_interval
end

if tokens <= 0 then
    return -1
else
    tokens = tokens - 1
    redis.call("HSET", key, "tokens", tokens, "timestamp", last_refill)
    redis.call("EXPIRE", key, refill_interval * max_tokens)
    return tokens
end

`

func IPRateLimitMiddleware(redisClient *redis.Client, maxTokens int, refillInterval time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			// fallback or block request if IP not found
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "cannot determine client IP"})
			return
		}

		key := fmt.Sprintf("rate_limit:ip:%s", ip)
		now := time.Now().Unix()

		result, err := redisClient.Eval(c, rateLimitLuaScript, []string{key},
			maxTokens, int(refillInterval.Seconds()), now).Int()

		if err != nil {
			log.Printf("Rate limit Redis error: %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "rate limit error"})
			return
		}

		if result == -1 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}

		c.Next()
	}
}

func AdvancedRateLimitMiddleware(redisClient *redis.Client, maxTokens int, refillInterval time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract user ID and device ID from request
		userID := c.GetHeader("X-User-ID")     // or from token
		deviceID := c.GetHeader("X-Device-ID") // or from JSON body

		if userID == "" || deviceID == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing user/device ID"})
			return
		}

		key := fmt.Sprintf("rate_limit:%s:%s", userID, deviceID)
		now := time.Now().Unix()

		result, err := redisClient.Eval(c, rateLimitLuaScript, []string{key},
			maxTokens, int(refillInterval.Seconds()), now).Int()

		if err != nil {
			log.Printf("Rate limit Redis error: %v", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "rate limit error"})
			return
		}

		if result == -1 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}
