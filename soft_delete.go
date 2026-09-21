package main

import (
	"context"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

func create_table_soft_delete(db *Db_data, s *Settings) {
	var err		error
	var sql		string
	var ctx		context.Context
	var cancel	context.CancelFunc

	sql = `
	CREATE EXTENSION IF NOT EXISTS pgcrypto;

	CREATE TABLE IF NOT EXISTS soft_delete (
		id UUID PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		password_hash TEXT,
		email TEXT UNIQUE NOT NULL,
		picture TEXT,
		joined TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW()
	);`
	ctx, cancel = db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql)
	if err != nil {
		log.Fatalf("error creating table: %s", err.Error())
	}
	go cleanup_soft_delete_table(db, s)
}

func cleanup_soft_delete_table(db *Db_data, s *Settings) {
	select_sql := `
	SELECT user_id, email FROM soft_delete WHERE created_at < NOW() - $1::interval
	`
	delete_sql := `
	DELETE FROM soft_delete WHERE user_id = ANY($1)
	`
	ticker := time.NewTicker(D_Soft_delete_time)
	defer ticker.Stop()
	for range ticker.C {
		var ids		[]uuid.UUID
		ctx, cancel := db.ctx()
		rows, err := db.pool.Query(ctx, select_sql, s.Delete.Delete_time.String())
		if err != nil {
			slog.Error("cleanup failed", "err", err)
			cancel()
			continue
		}
		for rows.Next() {
			var id		uuid.UUID
			var email	string

			err = rows.Scan(&id, &email)
			if err != nil {
 				slog.Error("scan failed", "err", err)
				continue
			}
			err = SoftDelete_Confirmation_Mail(s, email)
			if err != nil {
				slog.Error("mail failed", "err", err)
				continue
			}
			ids = append(ids, id)
		}
		rows.Close()
		cancel()
		del_ctx, del_cancel := db.ctx()
		if len(ids) > 0 {
			_, err = db.pool.Exec(del_ctx, delete_sql, ids)
			if err != nil {
				slog.Error("cleanup failed", "err", err)
			}
		}
		slog.Info("Cleaned soft_delete", "count", len(ids))
		del_cancel()
	}
}

//Note this use a GetUser, could send the struct user instead
func move_to_soft_delete(db *Db_data, email string) error {
	user, err := GetUserByMail(db, email)
	if err != nil {
		return err
	}
	err = AddUser_to_softdelete(db, user)
	if err != nil {
		return err
	}
	err = EraseUser(db, user.UserID.String())
	if err != nil {
		return err
	}
	return nil
}

func AddUser_to_softdelete(db *Db_data, user *User) error {
	var err		error
	var sql		string
	var ctx		context.Context
	var cancel	context.CancelFunc

	sql = `
	INSERT INTO soft_delete (id, name, password_hash, email, picture, joined) VALUES ($1, $2, $3, $4, $5, $6)
	`
	pass_hash, err := GetPassword(db, user.UserID.String())
	if err != nil {
		return err
	}
	ctx, cancel = db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, user.UserID, user.Name, pass_hash, user.Email, user.Picture, user.Joined)
	return err
}
