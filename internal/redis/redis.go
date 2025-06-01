package redis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// file-level log prefix for redis.go file
const redisFileLogPrefix = packageLogPrefix + "redis:"

type RedisClient struct {
	ctx    context.Context
	Client *redis.Client
}

// Initialize RedisClient with context and redis client
func NewRedisService(ctx context.Context, client *redis.Client) *RedisClient {
	return &RedisClient{
		ctx:    ctx,
		Client: client,
	}
}

// Implement Set
func (r *RedisClient) Set(key string, value interface{}, expiration time.Duration) error {
	const funcName = "Set:"
	funcLogPrefix := redisFileLogPrefix + funcName

	err := r.Client.Set(r.ctx, key, value, expiration).Err()
	if err != nil {
		log.Printf("%s failed to set key '%s': %v", funcLogPrefix, key, err)
		return fmt.Errorf("failed to set key '%s': %w", key, err)
	}
	log.Printf("%s key '%s' set successfully", funcLogPrefix, key)
	return nil
}

// Implement Get
func (r *RedisClient) Get(key string) (string, error) {
	const funcName = "Get:"
	funcLogPrefix := redisFileLogPrefix + funcName

	val, err := r.Client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		log.Printf("%s key '%s' does not exist", funcLogPrefix, key)
		return "", nil
	} else if err != nil {
		log.Printf("%s failed to get key '%s': %v", funcLogPrefix, key, err)
		return "", fmt.Errorf("failed to get key '%s': %w", key, err)
	}
	log.Printf("%s key '%s' retrieved successfully", funcLogPrefix, key)
	return val, nil
}

// Implement VerifyKey
func (r *RedisClient) VerifyKey(key string) (string, error) {
	const funcName = "VerifyKey:"
	funcLogPrefix := redisFileLogPrefix + funcName

	val, err := r.Client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		log.Printf("%s key '%s' does not exist", funcLogPrefix, key)
		return "", nil
	} else if err != nil {
		log.Printf("%s failed to get key '%s': %v", funcLogPrefix, key, err)
		return "", fmt.Errorf("failed to get key '%s': %w", key, err)
	}
	log.Printf("%s key '%s' verified successfully", funcLogPrefix, key)
	return val, nil
}

func (r *RedisClient) VerifyRefreshTokenJTI(jti string, tokenUserID string) error {
	const funcName = "VerifyRefreshTokenJTI:"
	funcLogPrefix := redisFileLogPrefix + funcName

	// Compose the Redis key
	key := "refresh_token:" + tokenUserID

	// Get the stored user ID using existing VerifyKey function
	storedJTI, err := r.VerifyKey(key)
	if err != nil {
		log.Printf("%s failed to verify refresh token JTI: %v", funcLogPrefix, err)
		return fmt.Errorf("failed to verify refresh token JTI: %w", err)
	}

	if storedJTI == "" {
		log.Printf("%s refresh token is invalid or has been revoked", funcLogPrefix)
		return fmt.Errorf("refresh token is invalid or has been revoked")
	}

	if storedJTI != jti {
		log.Printf("%s refresh token jti mismatch (stored: %s, provided: %s)", funcLogPrefix, storedJTI, jti)
		return fmt.Errorf("refresh token mismatch")
	}

	return nil
}

// Delete removes a key from Redis
func (r *RedisClient) DeleteKey(key string) error {
	const funcName = "DeleteKey:"
	funcLogPrefix := redisFileLogPrefix + funcName

	err := r.Client.Del(r.ctx, key).Err()
	if err != nil {
		log.Printf("%s failed to delete key '%s': %v", funcLogPrefix, key, err)
		return fmt.Errorf("failed to delete key '%s': %w", key, err)
	}

	log.Printf("%s key '%s' deleted successfully", funcLogPrefix, key)
	return nil
}

func (r *RedisClient) BlocklistTokenJTI(jti string, ttl time.Duration, userID string, reason string) error {
	const funcName = "BlocklistTokenJTI:"
	funcLogPrefix := redisFileLogPrefix + funcName

	if jti == "" {
		return errors.New("jti cannot be empty")
	}

	key := "blocklist:" + jti
	value := fmt.Sprintf("user:%s reason:%s", userID, reason)

	err := r.Client.Set(r.ctx, key, value, ttl).Err()
	if err != nil {
		log.Printf("%s failed to blocklist jti '%s': %v", funcLogPrefix, jti, err)
		return fmt.Errorf("failed to blocklist token jti '%s': %w", jti, err)
	}

	log.Printf("%s jti '%s' blocklisted (%s)", funcLogPrefix, jti, reason)
	return nil
}

func (r *RedisClient) VerifyAccessTokenJTINotBlacklisted(jti string) error {
	const funcName = "VerifyAccessTokenJTINotBlacklisted:"
	funcLogPrefix := redisFileLogPrefix + funcName

	if jti == "" {
		return errors.New("jti cannot be empty")
	}

	key := "blocklist:" + jti

	exists, err := r.Client.Exists(r.ctx, key).Result()
	if err != nil {
		log.Printf("%s error checking key '%s': %v", funcLogPrefix, key, err)
		return fmt.Errorf("error verifying token blocklist status: %w", err)
	}

	if exists > 0 {
		log.Printf("%s token with jti '%s' is blocklisted", funcLogPrefix, jti)
		return errors.New("access token has been revoked")
	}

	return nil
}

func (r *RedisClient) RemoveRefreshTokenJTI(userID string) error {
	const funcName = "RemoveRefreshTokenJTI:"
	funcLogPrefix := redisFileLogPrefix + funcName

	if userID == "" {
		return errors.New("userID and jti must not be empty")
	}

	key := fmt.Sprintf("refresh:%s", userID)
	err := r.DeleteKey(key)
	if err != nil {
		log.Printf("%s failed to delete key '%s': %v", funcLogPrefix, key, err)
		return fmt.Errorf("failed to delete refresh token jti from redis: %w", err)
	}

	log.Printf("%s successfully deleted refresh token jti for user '%s'", funcLogPrefix, userID)
	return nil
}

func Init() *RedisClient {
	const funcName = "Init:"
	funcLogPrefix := redisFileLogPrefix + funcName

	addr := os.Getenv("REDIS_ADDRESS")
	if addr == "" {
		log.Fatalf("%s REDIS_ADDRESS environment variable not set", funcLogPrefix)
	}

	password := os.Getenv("REDIS_PASSWORD")
	if password == "" {
		log.Printf("%s REDIS_PASSWORD not set, proceeding without authentication", funcLogPrefix)
	}

	db := 0

	Redis_service := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	ctx := context.Background()

	var err error
	for i := 0; i < 3; i++ {
		err = Redis_service.Ping(ctx).Err()
		if err == nil {
			log.Printf("%s Connected to Redis", funcLogPrefix)
			return NewRedisService(ctx, Redis_service)
		}
		log.Printf("%s Waiting for Redis to be ready (%d/3)...", funcLogPrefix, i+1)
		time.Sleep(2 * time.Second)
	}

	log.Fatalf("%s Redis connection failed after retries: %v", funcLogPrefix, err)

	return nil
}
