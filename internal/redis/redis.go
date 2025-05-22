package redis

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)




type RedisClient struct {
	ctx    context.Context
	client *redis.Client
}



// Initialize RedisClient with context and redis client
func NewRedisService(ctx context.Context, client *redis.Client) *RedisClient  {
	return &RedisClient{
		ctx:    ctx,
		client: client,
	}
}

// Implement Set
func (r *RedisClient) Set(key string, value interface{},expiration time.Duration) error {
	err := r.client.Set(r.ctx, key, value, expiration).Err()
	if err != nil {
		log.Printf("auth-system:internal:redis:redis:Set: failed to set key '%s': %v", key, err)
		return fmt.Errorf("failed to set key '%s': %w", key, err)
	}
	log.Printf("key '%s' set successfully", key)
	return nil
}

// Implement Get
func (r *RedisClient) Get(key string) (string, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		log.Printf("auth-system:internal:redis:redis:Get: key '%s' does not exist", key)
		return "", nil
	} else if err != nil {
		log.Printf("auth-system:internal:redis:redis:Get: failed to get key '%s': %v", key, err)
		return "", fmt.Errorf("failed to get key '%s': %w", key, err)
	}
	log.Printf("key '%s' retrieved successfully", key)
	return val, nil
}

// Implement Delete

func (r *RedisClient) VerifyKey(key string) (string, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err == redis.Nil {
		log.Printf("auth-system:internal:redis:redis:VerifyKey: key '%s' does not exist", key)
		return "", nil
	} else if err != nil {
		log.Printf("auth-system:internal:redis:redis:VerifyKey: failed to get key '%s': %v", key, err)
		return "", fmt.Errorf("failed to get key '%s': %w", key, err)
	}
	log.Printf("key '%s' verified successfully", key)
	return val, nil
}


func (r *RedisClient) VerifyRefreshTokenJTI(jti string, tokenUserID string) error {
    // Compose the Redis key
    key := "refresh_token:" + tokenUserID

    // Get the stored user ID using existing VerifyKey function
    storedJTI, err := r.VerifyKey(key)
    if err != nil {
		log.Printf("auth-system:internal:redis:redis:VerifyRefreshTokenJTI: failed to verify refresh token JTI: %v", err)
        return fmt.Errorf("failed to verify refresh token JTI: %w", err)
    }

    // If key doesn't exist, the token is revoked or reused
    if storedJTI == "" {
		log.Printf("auth-system:internal:redis:redis:VerifyRefreshTokenJTI: refresh token is invalid or has been revoked")
        return fmt.Errorf("refresh token is invalid or has been revoked")
    }

    // Check if the stored user ID matches the token's user ID
    if storedJTI != jti {
		log.Printf("auth-system:internal:redis:redis:VerifyRefreshTokenJTI: refresh token jti mismatch")
		fmt.Printf("stored JTI: %s, provided JTI: %s\n", storedJTI, jti)
        return fmt.Errorf("refresh token mismatch")
    }

    // Success: refresh token is valid
    return nil
}




// Delete removes a key from Redis
func (r *RedisClient) Delete(key string) error {
	err := r.client.Del(r.ctx, key).Err()
	if err != nil {
		log.Printf("auth-system:internal:redis:redis:Delete: failed to delete key '%s': %v", key, err)
		return fmt.Errorf("failed to delete key '%s': %w", key, err)
	}

	log.Printf("key '%s' deleted successfully", key)
	return nil
}



func Init() *RedisClient{
	addr := os.Getenv("REDIS_ADDRESS")
	if addr == "" {
		log.Fatal("auth-system:internal:redis:Init: REDIS_ADDR environment variable not set")
	}

	password := os.Getenv("REDIS_PASSWORD")
	if password == "" {
		log.Fatal("auth-system:internal:redis:Init: REDIS_PASSWORD not set, proceeding without authentication")
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
			log.Println("Connected to Redis")
			return NewRedisService(ctx , Redis_service)
			
		}
		log.Printf("Waiting for Redis to be ready (%d/3)...", i+1)
		time.Sleep(2 * time.Second)
	}

	log.Fatalf("auth-system:internal:redis:Init: Redis connection failed after retries: %v", err)
	
	return nil
}
