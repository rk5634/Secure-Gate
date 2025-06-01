package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// middlewareLogPrefix defines the logging prefix specific to middleware components.
const middlewareLogPrefix = packageLogPrefix + "middleware:"

// rateLimitLuaScript implements a token bucket algorithm in Redis Lua script for rate limiting.
// It manages tokens and refill timing to control request rates per key.
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

// IPRateLimitMiddleware enforces rate limiting based on client IP addresses.
// It uses a Redis-backed token bucket algorithm to control request rates per IP.
func IPRateLimitMiddleware(redisClient *redis.Client, maxTokens int, refillInterval time.Duration) gin.HandlerFunc {
	const funcName = "IPRateLimitMiddleware:"
	funcLogPrefix := middlewareLogPrefix + funcName

	return func(c *gin.Context) {
		ip := c.ClientIP()
		if ip == "" {
			log.Printf("%s unable to determine client IP", funcLogPrefix)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unable to determine client IP"})
			return
		}

		key := "rate_limit:ip:" + ip
		now := time.Now().Unix()

		result, err := redisClient.Eval(c, rateLimitLuaScript, []string{key}, maxTokens, int(refillInterval.Seconds()), now).Int()
		if err != nil {
			log.Printf("%s Redis evaluation error: %v", funcLogPrefix, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal rate limiting error"})
			return
		}

		if result == -1 {
			log.Printf("%s rate limit exceeded for IP: %s", funcLogPrefix, ip)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		log.Printf("%s allowed request for IP: %s, remaining tokens: %d", funcLogPrefix, ip, result)
		c.Next()
	}
}

// AdvancedRateLimitMiddleware enforces rate limiting using a composite key of user ID and device ID.
// This middleware supports fine-grained control by distinguishing different user devices.
func AdvancedRateLimitMiddleware(redisClient *redis.Client, maxTokens int, refillInterval time.Duration) gin.HandlerFunc {
	const funcName = "AdvancedRateLimitMiddleware:"
	funcLogPrefix := middlewareLogPrefix + funcName

	return func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		deviceID := c.GetHeader("X-Device-ID")

		if userID == "" || deviceID == "" {
			log.Printf("%s missing required user or device identifier, userID: %s, deviceID: %s", funcLogPrefix, userID, deviceID)
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing required user or device identifier"})
			return
		}

		key := "rate_limit:" + userID + ":" + deviceID
		now := time.Now().Unix()

		result, err := redisClient.Eval(c, rateLimitLuaScript, []string{key}, maxTokens, int(refillInterval.Seconds()), now).Int()
		if err != nil {
			log.Printf("%s Redis evaluation error: %v", funcLogPrefix, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal rate limiting error"})
			return
		}

		if result == -1 {
			log.Printf("%s rate limit exceeded for userID: %s deviceID: %s", funcLogPrefix, userID, deviceID)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		log.Printf("%s allowed request for userID: %s deviceID: %s, remaining tokens: %d", funcLogPrefix, userID, deviceID, result)
		c.Next()
	}
}
