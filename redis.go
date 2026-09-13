package main

import (
	"context"
	"time"
	"github.com/redis/go-redis/v9"
)

func (rds *Redis_data)ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), rds.ctx_timeout)
	return ctx, cancel
}

func Set_Redis(s *Settings, rds *Redis_data) {
	rds.rdb = redis.NewClient(
		&redis.Options{
			Addr: s.Redis.Addr,
		},
	)
	rds.Addr = s.Redis.Addr
	rds.ctx_timeout = s.Redis.Ctx_timeout
}

func (rds *Redis_data)Add_token(token string, remaining time.Duration) error {
	ctx, cancel := rds.ctx()
	defer cancel()
	status_cmd := rds.rdb.Set(ctx, "token:" + token, "revoked", remaining)
	return status_cmd.Err()
}

/*
true -> is revoked
false -> not revoked
*/
func (rds *Redis_data)Is_revoked(token string) (bool, error) {
	ctx, cancel := rds.ctx()
	defer cancel()
	n_instances, err := rds.rdb.Exists(ctx, "token:"+token).Result()
	if err != nil {
		return false, err
	}
	if n_instances > 0 {
		return true, nil
	}
	return false, nil
}

