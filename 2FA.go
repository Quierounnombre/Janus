package main

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/google/uuid"
	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"
)

func create_2FA_table(db *Db_data) {
	var sql		string
	var err		error

	sql = `
	CREATE TABLE IF NOT EXISTS pending_2fa (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		created_at TIMESTAMPTZ DEFAULT NOW(),
		name TEXT NOT NULL,
		password_hash TEXT,
		picture TEXT,
		purpose TEXT NOT NULL
	);`
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql)
	if err != nil {
		log.Fatalf("error creating table: %s", err.Error())
	}
	go cleanup_2FA_table(db)
}

func cleanup_2FA_table(db *Db_data) {
	var sql				string

	sql = `
	DELETE FROM pending_2fa WHERE created_at < NOW() - $1::interval
	`
	ticker := time.NewTicker(D_Reset_check_time)
	defer ticker.Stop()
	for range ticker.C {
		ctx, cancel := db.ctx()
		_, err := db.pool.Exec(ctx, sql, D_2FA_time.String())
		if err != nil {
			slog.Error("cleanup failed", "err", err)
		}
		slog.Info("Cleaned 2fa_pending")
		cancel()
	}
}

func Move_2FA_to_users(db *Db_data, id string) error {
	var sql		string
	var err		error
	var user	User
	var hash	string

	sql = `
	SELECT email, name, password_hash, picture FROM pending_2fa WHERE id=$1
	`
	ctx, cancel := db.ctx()
	defer cancel()
	row := db.pool.QueryRow(ctx, sql, id)
	err = row.Scan(&user.Email, &user.Name, &hash, &user.Picture)
	if err != nil {
		return err
	}
	err = AddUser(db, &user)
	if err != nil {
		return err
	}
	err = StorePassSimple(db, hash, user.Email, "users")
	if err != nil {
		return err
	}
	return nil
}

//This is before all checks, creates a 2FA, trusting that the data is correct.
func create_a_2FA(db *Db_data, user *User, password string, purpose string) (string, error) {
	var sql		string
	var err		error

	if user.Email == "" {
		return "", errors.New("email is empty")
	}
	sql = `
	INSERT INTO pending_2fa (id, email, name, picture, created_at, purpose) VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (email) DO UPDATE SET id = EXCLUDED.id, name = EXCLUDED.name, picture = EXCLUDED.picture, created_at = EXCLUDED.created_at, purpose = EXCLUDED.purpose
	`
	id := uuid.New().String()
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, id, user.Email, user.Name, user.Picture, time.Now(), purpose)
	if err != nil {
		return "", err
	}
	if purpose == P_Signup {
		err = StorePass(db, password, user.Email, D_2FA_DB)
		return id, err
	}
	return id, nil
}

func delete_a_2FA(db *Db_data, id string) error {
	var sql		string
	var err		error

	sql = `
	DELETE FROM pending_2fa WHERE id=$1
	`
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, id)
	return err
}

//This obtains a 2FA from DB, and returns the raw data
func Get2FA(db *Db_data, id string) (Two_FA_data, error) {
	var err		error
	var sql		string
	var d		Two_FA_data

	sql = `
	SELECT id, email, created_at, name, password_hash, picture, purpose FROM pending_2fa WHERE id = $1
	`
	ctx, cancel := db.ctx()
	defer cancel()
	row := db.pool.QueryRow(ctx, sql, id)
	err = row.Scan(&d.Id, &d.Email, &d.Created_at, &d.Name, &d.Password_hash, &d.Picture, &d.Purpose)
	return d, err
}

func Two_FA_login(db *Db_data, id string) error {
	var err		error
}

//This manage all the 2FA request and checks the correct use of such.
func Handle2FAVerified(
	s					*Settings,
	db					*Db_data,
	authMiddleware		*g_jwt.GinJWTMiddleware,
) gin.HandlerFunc {
	return func (c *gin.Context) {
		var err			error
		var data		Two_FA_data

		id := c.Param("id")
		data, err = Get2FA(db, id)
		if err != nil {
			slog.Error("Can't retrieve pending 2FA", "err", err)
			c.JSON(500, gin.H{"Error:": " Error in 2FA"})
			return 
		}
		switch data.Purpose {
		case P_Signup:
			2FA_signup()
		case P_Delete:
			Delete_user(db, data.Id)
		case P_Login:
			Two_FA_login(db, data.Id)
		default:
			fmt.Errorf("unknown 2fa purpose: %s", p)
		}
	}
}

func 2FA_signup(
	db				*Db_data,

) {
}
