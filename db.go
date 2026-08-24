package main

//Manage DB connecction and polling

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"context"
	"log"
	"time"
)

func connect_with_db(s *Settings, db *Db_data) {
	confg := set_up_pool_config(s)
	ctx, cancel := db.ctx()
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, confg)
	if err != nil {
		log.Fatalf("Error connecting to DB: %s", err.Error())
	}
	db.pool = pool
}

func set_up_pool_config(s *Settings) *pgxpool.Config {
	confg, err := pgxpool.ParseConfig(s.DB_url)
	if err != nil {
		log.Fatalf("Error creating config for db: %s", err.Error())
	}
	db_set := s.Db_set
	confg.MaxConnLifetime = db_set.Max_con_lifetime
	confg.MaxConns = db_set.Max_cons
	confg.MinConns = db_set.Min_cons
	confg.MinIdleConns = db_set.Min_idle_cons
	confg.HealthCheckPeriod = db_set.Health_check_period
	confg.MaxConnLifetimeJitter = db_set.Max_con_life_time_jitter
	confg.MaxConnIdleTime = db_set.Max_con_idle_time
	return confg
}

func (db *Db_data)ctx() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), db.ctx_timeout)
	return ctx, cancel
}

func Set_db_tables(db *Db_data) {
	create_table_user(db)
	create_2FA_table(db)
}

func Set_db(s *Settings, db *Db_data) {
	connect_with_db(s, db)
	db.ctx_timeout = s.Db_set.Ctx_timeout
	ctx, cancel := context.WithTimeout(context.Background(), 180 * time.Second)
	defer cancel()
	err := db.pool.Ping(ctx)
	if err != nil {
		log.Fatalf("Error unreliable connection: %s", err.Error())
	}
}
