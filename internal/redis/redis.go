package redis

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)




type redisService struct {
	ctx    context.Context
	client *redis.Client
}


var RedisClient *redisService

// Initialize RedisClient with context and redis client
func InitService(ctx context.Context, client *redis.Client) {
	RedisClient = &redisService{
		ctx:    ctx,
		client: client,
	}
}

// Implement Set
func (r *redisService) Set(key string, value interface{},expiration time.Duration) error {
	err := r.client.Set(r.ctx, key, value, expiration).Err()
	if err != nil {
		log.Printf("auth-system:internal:redis:redis:Set: failed to set key '%s': %v", key, err)
		return fmt.Errorf("failed to set key '%s': %w", key, err)
	}
	log.Printf("key '%s' set successfully", key)
	return nil
}

// Implement Get
func (r *redisService) Get(key string) (string, error) {
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

func Init() {
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
			InitService(ctx , Redis_service)
			return
		}
		log.Printf("Waiting for Redis to be ready (%d/3)...", i+1)
		time.Sleep(2 * time.Second)
	}

	log.Fatalf("auth-system:internal:redis:Init: Redis connection failed after retries: %v", err)
}
