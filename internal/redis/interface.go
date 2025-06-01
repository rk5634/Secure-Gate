package redis

type RedisService interface {
    Set(key string, value interface{}) error
    Get(key string) (string, error) // Returning a string for simplicity, or you might want to use a more complex return type
}