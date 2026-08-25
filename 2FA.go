package main

import (
	"errors"
	"log"
	"log/slog"
	"time"

	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
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
	var hash []byte
	//TODO: When doing P_Login one may need to expand this
	if purpose == P_Signup || purpose == P_Reset {
		hash, err = bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return "", err
		}
	}
	sql = `
		INSERT INTO pending_2fa (id, email, name, picture, created_at, purpose, password_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (email) DO UPDATE SET
			id = EXCLUDED.id,
			name = EXCLUDED.name,
			picture = EXCLUDED.picture,
			created_at = EXCLUDED.created_at,
			purpose = EXCLUDED.purpose,
			password_hash = COALESCE(NULLIF(EXCLUDED.password_hash, ''), pending_2fa.password_hash)
	`
	id := uuid.New().String()
	ctx, cancel := db.ctx()
	defer cancel()
	_, err = db.pool.Exec(ctx, sql, id, user.Email, user.Name, user.Picture, time.Now(), purpose, string(hash))
	if err != nil {
		return "", err
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

//This manage all the 2FA request and checks the correct use of such.
//For a 2FA request to exist, it must have already been checked elsewhere in the endpoint creating it,
//As an example: 2FA_Signup is generate at PassSignup and consumed here, there is no extra veridity check, other than the correct ID(Hard to guess due to rate limiting)
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
			Two_FA_signup(db, &data, c, authMiddleware)
		case P_Delete:
			Two_FA_erase(db, &data, c, authMiddleware)
		case P_Login:
			Two_FA_login(db, &data, c, authMiddleware)
		case P_Reset:
			Two_FA_reset(db, &data, c, authMiddleware)
		default:
			c.JSON(500, gin.H{"Error:": "unknown 2fa purpose: " + data.Purpose})
		}
	}
}

func Two_FA_signup(
	db					*Db_data,
	data				*Two_FA_data,
	c					*gin.Context,
	authMiddleware		*g_jwt.GinJWTMiddleware,
) {
	var err			error

	id := c.Param("id")
	_, err = GetUser(db, data.Email)
	if err != pgx.ErrNoRows {
		slog.Error("User already exists", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	err = Move_2FA_to_users(db, id)
	if err != nil {
		slog.Error("Error moving 2FA to users", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	err = delete_a_2FA(db, id)
	if err != nil {
		slog.Error("Error deleting 2FA user", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	user, err := GetUser(db, data.Email)
	if err != nil {
		slog.Error("Error obtaining user", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	err = Generate_access_token(user, authMiddleware, c)
	if err != nil {
		slog.Error("Couldn't generate a JWT", "err", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	slog.Info("user registered", "user_id", user.UserID)
}

func Two_FA_login(
	db					*Db_data,
	data				*Two_FA_data,
	c					*gin.Context,
	authMiddleware		*g_jwt.GinJWTMiddleware,
) {
	err := delete_a_2FA(db, data.Id)
	if err != nil {
		slog.Error("Error deleting 2FA user", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	user, err := GetUser(db, data.Email)
	if err != nil {
		slog.Error("Error retrieving user", "err", err)
		c.JSON(500,  gin.H{"Error:": " Error in 2FA"})
	}
	err = Generate_access_token(user, authMiddleware, c)
	if err != nil {
		slog.Error("Couldn't generate a JWT", "err", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
}

func Two_FA_erase(
	db					*Db_data,
	data				*Two_FA_data,
	c					*gin.Context,
	authMiddleware		*g_jwt.GinJWTMiddleware,
) {
	err := delete_a_2FA(db, data.Id)
	if err != nil {
		slog.Error("Error deleting 2FA user", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	err = EraseUser(db, data)
	if err != nil {
		slog.Error("Error erasing user", "err", err)
		c.JSON(500,  gin.H{"Error:": " Error in 2FA"})
		return
	}
	c.JSON(200, gin.H{"Success;": " User erased"})
}

func Two_FA_reset(
	db					*Db_data,
	data				*Two_FA_data,
	c					*gin.Context,
	authMiddleware		*g_jwt.GinJWTMiddleware,
) {
	err := delete_a_2FA(db, data.Id)
	if err != nil {
		slog.Error("Error deleting 2FA user", "err", err)
		c.JSON(500, gin.H{"Error:": " Error in 2FA"})
		return
	}
	err = StorePassSimple(db, data.Password_hash, data.Email, D_USERS_DB)
	if err != nil {
		slog.Error("password store failed", "err", err)
		c.JSON(500, gin.H{"Error:": " Error updating password"})
		return
	}
	c.JSON(200, gin.H{"Success;": "Password changed"})
}
