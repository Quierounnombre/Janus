package main

//Manage Auth process(OAuth only atm) and endpoints

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	validator "github.com/wagslane/go-password-validator"
)

//JWT MANUAL: https://pkg.go.dev/github.com/golang-jwt/jwt/v5#section-documentation
//HOLY BIBLE: https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1

var JWKS			keyfunc.Keyfunc // init once at startup
var jwkStorage		jwkset.Storage


//ADD STATE TOKEN
func generate_state_token() string {
	state := rand.Text()
	return (state)
}

func oauthlogin_url_with_query(s *Settings, state string) (*url.URL, error) {
	u, err := url.Parse(s.OAuth.Provider)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("client_id", s.Client_id)
	q.Set("redirect_uri", s.OAuth.Redirect_uri)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("access_type", "online")
	u.RawQuery = q.Encode()
	return u, nil
}

func OAuthLogin(s *Settings) gin.HandlerFunc {
	return func(c *gin.Context) {
		oauth_cookies := sessions.Default(c)
		state := generate_state_token()
		oauth_cookies.Set("state", state)
		err := oauth_cookies.Save()
		if err != nil {
			slog.Error("oauth login: session save failed", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error saving cookies": err.Error()})
			return
		}
		auth_url, err := oauthlogin_url_with_query(s, state)
		if err != nil {
			slog.Error("oauth login: auth url generation failed", "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"Error generating redirect url": err.Error()})
			return
		}
		//Should need login attemp tracing
		c.Redirect(307, auth_url.String())
	}
}

func oauthcallback_url_with_query(s *Settings, code string) (*url.URL, url.Values, error) {
	u, err := url.Parse(s.OAuth.Token_provider)
	if err != nil {
		return nil, nil, err
	}
	form := url.Values{}
	form.Set("client_id", s.Client_id)
	form.Set("client_secret", s.Client_secret)
	form.Set("code", code)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", s.OAuth.Redirect_uri)
	return u, form, nil
}

func OAuthCallback(s *Settings, db *Db_data, authMiddleware *g_jwt.GinJWTMiddleware) gin.HandlerFunc {
	return func(c *gin.Context) {
		var state			string
		var response_state	string
		var s_oauth_code	string
		var id_token		string
		var err				error
		var ok				bool
		var oauth_cookies	sessions.Session
		var token_url		*url.URL
		var resp			*http.Response
		var body			map[string]interface{}
		var decoder			*json.Decoder
		var claims			jwt.MapClaims
		var jwt_token		*jwt.Token
		var user			*User
		var storage_data	User

		oauth_cookies = sessions.Default(c)
		state, ok = oauth_cookies.Get("state").(string)
		if !ok {
			c.JSON(400, gin.H{"error": "missing state"})
			return
		}
    	oauth_cookies.Delete("state")
		err = oauth_cookies.Save()
		if err != nil {
			slog.Error("oauth callback: session save failed", "error", err)
			c.JSON(500, gin.H{"error saving cookies": err.Error()})
			return
		}
		response_state = c.Query("state")
		if response_state == "" {
			c.JSON(401, gin.H{"error": "missing state"})
			return
		}
		if state != response_state {
			c.JSON(400, gin.H{"error": "mismatch state token"})
			return
		}
		s_oauth_code = c.Query("code")
		if s_oauth_code == "" {
			c.JSON(400, gin.H{"error": "Missing auth code"})
			return
		}
		token_url, form, err := oauthcallback_url_with_query(s, s_oauth_code)
		if err != nil {
			slog.Error("oauth callback: token url generation failed", "error", err)
			c.JSON(500, gin.H{"error in response": err.Error()})
			return
		}
		resp, err = http.PostForm(token_url.String(), form)
		if err != nil {
			slog.Error("oauth callback: token exchange request failed", "error", err)
			c.JSON(502, gin.H{"error in response": err.Error()})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			slog.Error("oauth callback: bad status from provider", "status", resp.StatusCode)
			c.JSON(502, gin.H{"error": "bad status code"})
			return
		}
		decoder = json.NewDecoder(resp.Body)
		err = decoder.Decode(&body)
		if err != nil {
			slog.Error("oauth callback: can't decode the body", "error", err)
			c.JSON(502, gin.H{"error": err.Error()})
			return
		}
		id_token, ok = body["id_token"].(string)
		if !ok {
			slog.Error("missing id_token in body")
			c.JSON(502, gin.H{"error": "Missing id token"})
			return
		}
		jwt_token, err = jwt.Parse(id_token, JWKS.Keyfunc,
			jwt.WithIssuer(s.OAuth.Issuer_url),
			jwt.WithAudience(s.Client_id),
			jwt.WithExpirationRequired(),
		)
		if err != nil {
			c.JSON(502, gin.H{"error": "invalid token"})
			return
		}
		claims, ok = jwt_token.Claims.(jwt.MapClaims)
		if !ok {
			slog.Error("missing jwt_claims")
			c.JSON(502, gin.H{"error": "Missing claims"})
			return
		}
		storage_data.Name = fmt.Sprintf("%v", claims["given_name"])
		storage_data.Email = fmt.Sprintf("%v", claims["email"])
		storage_data.Picture = fmt.Sprintf("%v", claims["picture"])
		user, err = Login_or_ADD_User(db, &storage_data)
		if err != nil {
			slog.Error("oauth callback: login or add user failed", "email", storage_data.Email, "error", err)
			c.JSON(500, gin.H{"Error creating user": err.Error()})
			return
		}
		c.Set("oauth_provider", s.OAuth.Provider)
		err = Generate_access_token(user, authMiddleware, c)
		if err != nil {
			slog.Error("Couldn't generate a JWT", "err", err)
			c.JSON(500, gin.H{"Error authenticating user": err.Error()})
			return
		}
		slog.Info("oauth callback success", "provider", s.OAuth.Provider, "user_id", user.UserID)
	}
}

func Expose_pub_key(s *Settings) gin.HandlerFunc {
	return func(c *gin.Context) {
		resp, err := jwkStorage.JSON(c.Request.Context())
		if err != nil {
			slog.Error("Error providing public key", "err", err)
			c.JSON(500, gin.H{"Error Exposing key": err.Error()})
			return
		}
		c.Data(200, "application/json", resp)
	}
}

func PassLogin(
	db				*Db_data,
	authMiddleware	*g_jwt.GinJWTMiddleware,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req		LoginRequest
		var err		error
		var match	bool
		var user	*User

		err = c.ShouldBindJSON(&req)
		if err != nil {
			slog.Info("bind failed", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if req.Email == "" {
			slog.Info("missing email", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing email"})
			return
		}
		if req.Password == "" {
			slog.Info("missing password", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing password"})
			return
		}
		match, err = CheckUserPassword(db, req)
		if err != nil {
			//Log already done in check user password
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error checking password"})
			return
		}
		if match == false {
			slog.Warn("User password don't match", "user", req.Email)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Password don't match"})
			return
		}
		user, err = GetUser(db, req.Email)
		if err != nil {
			slog.Error("Couldn't retrieve user from DB", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		err = Generate_access_token(user, authMiddleware, c)
		if err != nil {
			slog.Error("Couldn't generate a JWT", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		slog.Info("password login", "user_id", user.UserID)
	}
}

func Pass_Singup(
	s				*Settings,
	db				*Db_data,
	authMiddleware	*g_jwt.GinJWTMiddleware,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req		SignUpRequest
		var err		error
		var user	User

		err = c.ShouldBindJSON(&req)
		if err != nil {
			slog.Info("bind failed", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		if req.Email == "" {
			slog.Info("missing mail", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing email"})
			return
		}
		if req.Name == "" {
			slog.Info("missing name", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing name"})
			return
		}
		if req.Password == "" {
			slog.Info("missing password", "err", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing password"})
			return
		}
		err = validator.Validate(req.Password, s.Password.Min_entropy)
		if err != nil {
			slog.Info("Weak Password", "err", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return 
		}
		user.Email = req.Email
		user.Name = req.Name
		id, err := create_a_2FA(db, &user, req.Password, P_Signup)
		if err != nil {
			slog.Error("2FA creating user", "err", err)
			c.JSON(500, gin.H{"Error:": " Error in 2FA"})
			return
		}
		err = TwoFA_Mail(s, db, req.Email, id)
		if err != nil {
			slog.Error("2FA sending email", "err", err)
			c.JSON(500, gin.H{"Error:": " Error in 2FA"})
			return
		}
		slog.Info("sended 2FA email", "email", user.Email)
		c.JSON(200, gin.H{"result": "Check your email"})
	}
}

func ConfirmPage() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.HTML(http.StatusOK, "confirm.html", gin.H{
			"Action": "/2FA_validate/" + c.Param("id"),
		})
	}
}

func Generate_access_token(
	user				*User,
	authMiddleware		*g_jwt.GinJWTMiddleware,
	c					*gin.Context,
) error {
	c.Set(authMiddleware.IdentityKey, user)
	token, err := authMiddleware.TokenGenerator(c.Request.Context(), user)
	if err != nil {
		return err
	}
	authMiddleware.SetCookie(c, token.AccessToken)
	authMiddleware.SetRefreshTokenCookie(c, token.RefreshToken)
	if authMiddleware.LoginResponse != nil {
		authMiddleware.LoginResponse(c, token)
	}
	return nil
}
