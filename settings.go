package main

import (
	"context"
	"html/template"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
	"github.com/golang-jwt/jwt/v5"
)

func load_settings_from_env(s *Settings) {
	content, err := os.ReadFile(D_config_path)
	if err != nil {
		log.Fatalf("config: %s", err.Error())
	}
	err = yaml.Unmarshal(content, s)
	if err != nil {
		log.Fatalf("config: %s", err.Error())
	}
	s.Session_key = parse_string_env("SESSION_KEY")
	s.Jwt_priv_key = parse_string_env("JWT_PRIV_KEY")
	s.Jwt_priv_key = strings.ReplaceAll(s.Jwt_priv_key, `\n`, "\n")
	s.Jwt_pub_key = parse_string_env("JWT_PUB_KEY")
	s.Jwt_pub_key = strings.ReplaceAll(s.Jwt_pub_key, `\n`, "\n")
	s.DB_url = parse_string_env("DATABASE_URL")
	s.Client_id = parse_string_env("CLIENT_ID")
	s.Client_secret = parse_string_env("CLIENT_SECRET")
	s.Mail_key = parse_string_env("MAIL_KEY")
}

func parse_string_env(key string) (string) {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("config: %s: missing", key)
	}
	return v
}

func Set_cors_config(s *Settings) cors.Config {
	config := cors.DefaultConfig()
	config.AllowAllOrigins				= s.Cors.AllowAllOrigins
	config.AllowPrivateNetwork			= s.Cors.AllowPrivateNetwork
	config.AllowCredentials				= s.Cors.AllowCredentials
	config.AllowWildcard				= s.Cors.AllowWildcard
	config.AllowBrowserExtensions		= s.Cors.AllowBrowserExtensions
	config.AllowWebSockets				= s.Cors.AllowWebsockets
	config.AllowFiles					= s.Cors.AllowFiles
	config.AllowOrigins					= s.Cors.AllowOrigins
	config.AllowMethods					= s.Cors.AllowMethods
	config.AllowHeaders					= s.Cors.AllowHeaders
	config.MaxAge						= s.Cors.MaxAge
	config.OptionsResponseStatusCode	= s.Cors.OptionsResponseStatus
	return config
}

func Set_endpoints(
	s			*Settings,
	eng			*gin.Engine,
	db			*Db_data,
	handle		*g_jwt.GinJWTMiddleware,
) {
	eng.GET("/OAuthLogin", OAuthLogin(s))
	eng.GET("/OAuthCallback", OAuthCallback(s, db, handle))
	eng.POST("/PassLogin", PassLogin(db, handle))
	eng.POST("/PassSignup", Pass_Singup(s, db, handle))
	eng.POST("/2FA_validate/:id", Handle2FAVerified(s, db, handle))
	eng.GET("/2FA_validate/:id", ConfirmPage())
	eng.POST("/PassReset", ResetPass(s, db))
	eng.POST("/Reset_pass_new/:id", ResetPassSend(s, db))
	eng.POST("/Refresh", handle.RefreshHandler)
	eng.GET("/Public-key", Expose_pub_key(s))
	eng.NoRoute(handle.MiddlewareFunc(), handleNoRoute())
	auth := eng.Group("/User/", handle.MiddlewareFunc())
	{
		auth.GET("/Profile", GetProfile(db))
		auth.GET("/Logout", handle.LogoutHandler)
		auth.DELETE("/Erase_user", RequestEraseUser(s, db))
	}
	if s.Release_mode == gin.DebugMode {
		test_endpoints(s, eng)
	}
}

func Set_JWT(s *Settings) *g_jwt.GinJWTMiddleware {
	Middleware, err := g_jwt.New(init_jwt_params(s))
	if err != nil {
		log.Fatalf("JWT Error:" + err.Error())
	}
	err = Middleware.MiddlewareInit()
	if err != nil {
		log.Fatalf("Middleware init Error:" + err.Error())
	}
	return Middleware
}

func Set_RateLimiter(s *Settings) *RateLimiter {
	rl := RateLimiter {
		buckets: make(map[string]*Bucket),
		max: s.Limiter.Max_request,
		reset_time: s.Limiter.Reset_time,
		ref_amount: s.Limiter.Refill,
	}
	go rl.Refill()
	return (&rl)
}

func initJWKS_client(s *Settings) {
	k, err := keyfunc.NewDefaultCtx(context.Background(), []string{s.OAuth.JKWS})
	if err != nil {
		log.Fatalf("JWKS init Error:" + err.Error())
	}
	JWKS = k
}

func initJWKS_server(s *Settings) {
	rsaPub, err := jwt.ParseRSAPublicKeyFromPEM([]byte(s.Jwt_pub_key))
	if err != nil {
		log.Fatalf("Error reading public key: " + err.Error())
	}
	options := jwkset.JWKOptions {
		Marshal: jwkset.JWKMarshalOptions{Private: false},
		Metadata: jwkset.JWKMetadataOptions{
			KID: "Calatayud",
			ALG: jwkset.AlgRS256,
			USE: jwkset.UseSig,
		},
	}
	jwk, err := jwkset.NewJWKFromKey(rsaPub, options)
	if err != nil {
		log.Fatalf("Error creating jwkstorage: " + err.Error())
	}
	jwkStorage = jwkset.NewMemoryStorage()
	err = jwkStorage.KeyWrite(context.Background(), jwk)
	if err != nil {
		log.Fatalf("Error writing into storage: " + err.Error())
	}
}

func load_templates() {
	tmpls = template.Must(template.ParseFS(templateFS, "templates/*.html"))
	slog.Info("Loaded templates", "size: ", len(tmpls.Templates()))
}

func Set_gin(s *Settings, db *Db_data) *gin.Engine {
	load_templates()
	Middleware := Set_JWT(s)
	init_mail(s)
	initJWKS_client(s)
	initJWKS_server(s)
	store := cookie.NewStore([]byte(s.Session_key))
	config := Set_cors_config(s)
	rl :=  Set_RateLimiter(s)
	eng := gin.New()
	eng.Use(gin.Recovery())
	eng.Use(gin.Logger())
	eng.Use(cors.New(config))
	eng.SetHTMLTemplate(tmpls)
	if s.Release_mode == gin.ReleaseMode {
		eng.Use(rl.Middleware())
	}
	eng.Use(sessions.Sessions("state_session", store))
	Set_endpoints(s, eng, db, Middleware)
	return eng
}
