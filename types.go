package main

import (
	"context"
	"sync"
	"time"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/gomail.v2"
)

//----------------------------------------------------------------------------------------------SETTINGS

/*
github.com/jackc/pgx/v5/pgxpool

DB config for pgxpool
*/
type Db_settings struct {
	Max_cons					int32				`yaml:"max_cons"`
	Min_cons					int32				`yaml:"min_cons"`
	Min_idle_cons				int32				`yaml:"min_idle_cons"`
	Health_check_period			time.Duration		`yaml:"health_check_period"`
	Max_con_lifetime			time.Duration		`yaml:"max_con_lifetime"`
	Max_con_life_time_jitter	time.Duration		`yaml:"max_con_lifetime_jitter"`
	Max_con_idle_time			time.Duration		`yaml:"max_con_idle_time"`
	Ctx_timeout					time.Duration		`yaml:"ctx_timeout"`
}

/*
https://pkg.go.dev/github.com/gin-contrib/cors#Config

Cors config
*/
type Cors_settings struct {
	AllowAllOrigins			bool			`yaml:"allow_all_origins"`
	AllowPrivateNetwork		bool			`yaml:"allow_private_network"`
	AllowCredentials        bool			`yaml:"allow_credentials"`
	AllowWildcard			bool			`yaml:"allow_wildcard"`
	AllowBrowserExtensions	bool			`yaml:"allow_browser_extensions"`
	AllowWebsockets			bool			`yaml:"allow_websockets"`
	AllowFiles				bool			`yaml:"allow_files"`
	AllowOrigins			[]string		`yaml:"allow_origins"`
	AllowMethods			[]string		`yaml:"allow_methods"`
	AllowHeaders			[]string		`yaml:"allow_headers"`
	MaxAge					time.Duration	`yaml:"max_age"`
	OptionsResponseStatus	int				`yaml:"options_response_status"`
}

/*
"github.com/appleboy/gin-jwt/v3"
"github.com/appleboy/gin-jwt/v3/core"
"github.com/golang-jwt/jwt/v5"

JWT configs
*/
type Jwt_settings struct {
	Realm				string				`yaml:"realm"`
	TokenLookup			string				`yaml:"token_lookup"`
	TokenHeadName		string				`yaml:"token_head_name"`
	CookieDomain		string				`yaml:"cookie_domain"`
	CookieName			string				`yaml:"cookie_name"`
	SendCookie			bool				`yaml:"send_cookie"`
	SecureCookie		bool				`yaml:"secure_cookie"`
	SendAuthorization	bool				`yaml:"send_authorization"`
	CookieHTTPOnly		bool				`yaml:"cookie_http_only"`
	CookieSameSite		int					`yaml:"cookie_same_site"`
	CookieMaxAge		time.Duration		`yaml:"cookie_max_age"`
	Timeout				time.Duration		`yaml:"timeout"`
	MaxRefresh			time.Duration		`yaml:"max_refresh"`
}

type OAuth_settings struct {
	Provider			string				`yaml:"provider"`
	Redirect_uri		string				`yaml:"redirect_uri"`
	Token_provider		string				`yaml:"token_provider"`
	Issuer_url			string				`yaml:"issuer_url"`
	JKWS				string				`yaml:"jwks"`
}

type Mail_settings struct {
	Provider			string				`yaml:"provider"`
	User				string				`yaml:"user"` //NOTE, THIS MAY NEED CHANGE WHEN USING different emails, ex: support@company and RRHH@company
	From				string				`yaml:"from"` //WHO SENDS THE EMAIL
	Queue_size			int					`yaml:"queue_size"`
	Max_workers			int					`yaml:"max_workers"`
	Min_workers			int					`yaml:"min_workers"`
	Worker_per_qeueu	int					`yaml:"worker_per_queue"`
	Sleep_time			time.Duration		`yaml:"sleep_time"`
	Port				int					`yaml:"port"`
	dialer				*gomail.Dialer
	queue				chan *gomail.Message
	retry_queue			chan *gomail.Message
}

type Logger_settings struct {
	Path				string				`yaml:"path"`
	Level				string				`yaml:"level"`
	MaxSize				int					`yaml:"max_size"`
	MaxAge				int					`yaml:"max_age"`
	MaxBackups			int					`yaml:"max_backups"`
	LocalTime			bool				`yaml:"local_time"`
	Compress			bool				`yaml:"compress"`
	Source				bool				`yaml:"source"`
}

type Password_settings struct {
	Min_entropy			float64				`yaml:"min_entropy"`
}

type Settings struct {
	Release_mode		string				`yaml:"release_mode"`
	Frontend			string				`yaml:"frontend"`
	Port				string				`yaml:"port"`
	Db_set				Db_settings			`yaml:"db"`
	Cors				Cors_settings		`yaml:"cors"`
	Jwt					Jwt_settings		`yaml:"jwt"`
	OAuth				OAuth_settings		`yaml:"oauth"`
	Limiter				Rate_limits			`yaml:"rate"`
	Mail				Mail_settings		`yaml:"mail"`
	Logger				Logger_settings		`yaml:"logger"`
	Password			Password_settings	`yaml:"password"`

	// injected from .env

	Mail_key			string
	Session_key			string
	Jwt_priv_key		string
	Jwt_pub_key			string
	DB_url				string
	Client_id			string
	Client_secret		string
}

//------------------------------------------------------------------------------------------------------DATA

type Db_data struct {
	pool			*pgxpool.Pool
	cancel			context.CancelFunc
	ctx_timeout		time.Duration
}

type User struct {
	Name			string		`json:"name"`
	Email			string		`json:"email"`
	UserID			uuid.UUID	`json:"id"`
	Picture			string		`json:"picture"`
}

type LoginRequest struct {
	Email			string		`json:"email"`
	Password		string		`json:"password"`
}

type SignUpRequest struct {
	Email		string		`json:"email"`
	Password	string		`json:"password"`
	Name		string		`json:"name"`
}

//------------------------------------------------------------------------------------------------------LIMITER

type Bucket struct {
	tokens		uint
}

type RateLimiter struct {
	mu			sync.Mutex
	buckets		map[string]*Bucket
	reset_time	time.Duration
	max			uint
	ref_amount	uint
}

type Rate_limits struct {
	Max_request		uint			`yaml:"max_request"`
	Reset_time		time.Duration	`yaml:"reset_interval"`
	Refill			uint			`yaml:"refill"`
}

//------------------------------------------------------------------------------------------------------2FA


type Two_FA_data struct {
	Id				string
	Email			string
	Created_at		time.Time
	Name			string
	Password_hash	string
	Picture			string
	Purpose			string
}
