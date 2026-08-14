package main

//Manage user endpoints(creation, deletion, list)

//TODO: A way to update user changes

import (
	"context"
	"log"
	"log/slog"

	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
	validator "github.com/wagslane/go-password-validator"
)

func create_table_user(db *Db_data) {
	var err		error
	var sql		string
	var ctx		context.Context
	var cancel	context.CancelFunc

	sql = `
	CREATE EXTENSION IF NOT EXISTS pgcrypto;

	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		name TEXT NOT NULL,
		password_hash TEXT,
		email TEXT UNIQUE NOT NULL,
		picture TEXT,
		joined TIMESTAMPTZ DEFAULT NOW()
	);`
	ctx, cancel = db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql)
	if err != nil {
		log.Fatalf("error creating table: %s", err.Error())
	}
}

func AddUser(db *Db_data, user *User) error {
	var err		error
	var sql		string
	var ctx		context.Context
	var cancel	context.CancelFunc

	sql = `
	INSERT INTO users (name, email, picture) VALUES ($1, $2, $3)
	`
	ctx, cancel = db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, user.Name, user.Email, user.Picture)
	return err
}

func GetUser(db *Db_data, email string) (*User, error) {
	var err		error
	var sql		string
	var ctx		context.Context
	var cancel	context.CancelFunc
	var row		pgx.Row
	var user	*User

	user = new(User)
	sql = `
	SELECT name, email, id, picture FROM users WHERE email=$1
	`
	ctx, cancel = db.ctx()
	defer cancel()
	row = db.pool.QueryRow(ctx, sql, email)
	err = row.Scan(&user.Name, &user.Email, &user.UserID, &user.Picture)
	return user, err
}

//This hassed the password
//IMPORTANT, THE TABLE MUST CONTAIN A FIELD called "password_hash" and anothe called "email" if not, caos ensues.
func StorePass(db *Db_data, pass string, email string, table string) error {
	var err			error
	var sql			string
	var pass_hash	[]byte

	sql = `
	UPDATE ` + table + ` SET password_hash=$1 WHERE email=$2
	`
	pass_hash, err = bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, string(pass_hash), email)
	return err
}

//Store the password "plain" used ONLY to move already hashed password from one place to another
//IMPORTANT, THE TABLE MUST CONTAIN A FIELD called "password_hash" and anothe called "email" if not, caos ensues.
func StorePassSimple(db *Db_data, pass string, email string, table string) error {
	var err			error
	var sql			string

	sql = `
	UPDATE ` + table + ` SET password_hash=$1 WHERE email=$2
	`
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, string(pass), email)
	return err
}

//Checks if the user exist, and the password is the correct one
func CheckUserPassword(db *Db_data, req LoginRequest) (bool, error) {
	var pass_hash	string
	var err			error
	var sql			string
	var row			pgx.Row

	sql = `
	SELECT password_hash FROM users WHERE email=$1
	`
	ctx, cancel := db.ctx()
	defer cancel()
	row = db.pool.QueryRow(ctx, sql, req.Email)
	err = row.Scan(&pass_hash)
	if err != nil {
		slog.Warn("User not existing in DB", "err", err, "user", req.Email)
		return false, err
	}
	if pass_hash == "" {
		slog.Info("User exist as OAuth user", "err", err, "user", req.Email)
		return false, err
	}
	err = bcrypt.CompareHashAndPassword([]byte(pass_hash), []byte(req.Password))
	if err != nil {
		slog.Error("Error at comparing hashes", "err", err)
		return false, err
	}
	return true, err
}

func Login_or_ADD_User(db *Db_data, storage_data *User) (*User, error) {
	var tmp_email	string
	var sql			string
	var err			error
	var row			pgx.Row
	var ctx			context.Context
	var cancel		context.CancelFunc
	var user		*User

	sql = `
	SELECT email FROM users WHERE email=$1
	`
	ctx, cancel = db.ctx()
	defer cancel()
	row = db.pool.QueryRow(ctx, sql, storage_data.Email)
	err = row.Scan(&tmp_email)
	if err == pgx.ErrNoRows {
		err = nil
		err = AddUser(db, storage_data)
	} else if err != nil {
		return user, err
	}
	user, err = GetUser(db, storage_data.Email)
	return user, err
}

func EraseUser(
	db		*Db_data,
	data	*Two_FA_data,
) error {
	var sql		string
	var err		error
	var ctx		context.Context
	var cancel	context.CancelFunc

	sql = `
	DELETE FROM users WHERE email=$1
	`
	ctx, cancel = db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, data.Email)
	return err
}

func GetProfile(db *Db_data) gin.HandlerFunc {
	return func(c *gin.Context) {
		var claims		jwt.MapClaims
		var err			error
		var email		string
		var user		*User

		claims = g_jwt.ExtractClaims(c)
		email = claims["email"].(string)
		if email == "" {
			slog.Error("JWT missing email field", "err", err)
			c.JSON(401, gin.H{"Error:": " retrieving claims from jwt"})
			return
		}
		user, err = GetUser(db, email)
		if err != nil {
			slog.Error("User dosen't exist", "err", err)
			c.JSON(500, gin.H{"Error:": " obtaining user from db"})
			return
		}
		c.JSON(200, gin.H{
			"email": user.Email,
			"name": user.Name,
			"picture": user.Picture,
		})
	}
}

func ResetPass(s *Settings, db *Db_data) gin.HandlerFunc {
	return func (c *gin.Context) {
		var err		error
		var body	struct {
			Email	string `json:"email"`
		}

		err = c.ShouldBindJSON(&body)
		if err != nil {
			slog.Warn("Missing body on a resetpass request", "err", err)
			c.JSON(400, gin.H{"Error:": " Invalid content"})
			return 
		}
		if body.Email == "" {
			slog.Warn("Missing email on a resetpass request", "err", err)
			c.JSON(400, gin.H{"Error:": " Missing email"})
			return
		}
		_, err = GetUser(db, body.Email)
		if err != nil {
			//NOT LEAKING WHICH EMAILS EXIST
			slog.Warn("Someone tryed to moddify the password for an account that dosent exist", "err", err)
			c.JSON(200, gin.H{"result": "Check your email"})
			return
		}
		err = Mail_Reset_Pass(s, db, body.Email)
		if err != nil {
			slog.Error("Couldn't send the reset_pass_mail", "err", err)
			c.JSON(500, gin.H{"Error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"result": "Check your email"})
	}
}

func ResetPassSend(s *Settings, db *Db_data) gin.HandlerFunc {
	return func (c *gin.Context) {
		var err			error
		var db_email	string
		var body		struct {
			NewPass		string `json:"newpass"`
			Email		string `json:"email"`
		}

		err = c.ShouldBindJSON(&body)
		if err != nil {
			slog.Warn("Missing body on a resetpasssend request", "err", err)
			c.JSON(400, gin.H{"Error:": " Invalid content"})
			return 
		}
		if body.Email == "" {
			slog.Warn("Missing email", "err", err)
			c.JSON(400, gin.H{"Error:": " Missing email"})
			return
		}
		if body.NewPass == "" {
			slog.Warn("Missing newpass", "err", err)
			c.JSON(400, gin.H{"Error:": " Missing password"})
			return
		}
		id := c.Param("id")
		db_email, err = GetPassReset(db, id)
		if err != nil {
			slog.Warn("password reset token not found", "err", err)
			c.JSON(500, gin.H{"Error:": " Error updating password"})
			return 
		}
		if db_email != body.Email {
			slog.Warn("password reset email mismatch")
			c.JSON(400, gin.H{"Error:": " Error updating password"})
			return 
		}
		err = validator.Validate(body.NewPass, s.Password.Min_entropy)
		if err != nil {
			slog.Info("Weak new Password", "err", err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		err = StorePass(db, body.NewPass, body.Email, "users")
		if err != nil {
			slog.Error("password store failed", "err", err)
			c.JSON(500, gin.H{"Error:": " Error updating password"})
			return
		}
		err = delete_a_password_reset(db, id)
		if err != nil {
			slog.Error("password reset token delete failed", "err", err)
			c.JSON(500, gin.H{"Error:": " Error updating password"})
			return
		}
		slog.Info("password reset successful for ", "email", body.Email)
		c.JSON(200, gin.H{"Success": "Password updated"})
	}
}
