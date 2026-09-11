package main

import (
	"log/slog"
	"net/http"
	"time"

	g_jwt "github.com/appleboy/gin-jwt/v3"
	"github.com/appleboy/gin-jwt/v3/core"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func init_jwt_params(s *Settings, rds *Redis_data) *g_jwt.GinJWTMiddleware {
	return &g_jwt.GinJWTMiddleware{
		Realm:				s.Jwt.Realm,
		PrivKeyBytes:		[]byte(s.Jwt_priv_key),
		PubKeyBytes:		[]byte(s.Jwt_pub_key),
		SigningAlgorithm:	"RS256",
		Timeout:			s.Jwt.Timeout,
		MaxRefresh:			s.Jwt.MaxRefresh,
		IdentityKey:		D_JWT_identity_key,
		PayloadFunc:		payload_func(),
		IdentityHandler:	identity_handler(rds),
		Authenticator:		authenticator(),
		Authorizer:			authorizer(),
		Unauthorized:		unauthorized(),
		LogoutResponse:		logout_response(rds),
		LoginResponse:		login_response(),
		TokenLookup:		s.Jwt.TokenLookup,
		TokenHeadName:		s.Jwt.TokenHeadName,
		TimeFunc:			time.Now,
		SendCookie:			s.Jwt.SendCookie,
		SecureCookie:		s.Jwt.SecureCookie,
		CookieSameSite:		http.SameSite(s.Jwt.CookieSameSite),
		CookieHTTPOnly:		s.Jwt.CookieHTTPOnly,
		CookieMaxAge:		s.Jwt.CookieMaxAge,
		CookieDomain:		s.Jwt.CookieDomain,
		CookieName:			s.Jwt.CookieName,
		SendAuthorization:	s.Jwt.SendAuthorization,
	}
}
 
func payload_func() func(data any) jwt.MapClaims {
	return func(data any) jwt.MapClaims {
		value, ok := data.(*User)
		if !ok {
			return jwt.MapClaims{}
		}
		return jwt.MapClaims{
			D_JWT_identity_key: value.UserID.String(),
		}
	}
}

func identity_handler(rds *Redis_data) func(c *gin.Context) any {
	return func(c *gin.Context) any {
		claims := g_jwt.ExtractClaims(c)
		id_str, ok := claims[D_JWT_identity_key].(string)
		if !ok {
			return nil
		}
		id, err := uuid.Parse(id_str)
		if err != nil {
			return nil
		}
		token := g_jwt.GetToken(c)
		revoked, err := rds.Is_revoked(token)
		if err != nil {
			slog.Error("Redis check failed", "err", err)
			return nil
		}
		if revoked {
			return nil
		}
		return &User{
			UserID: id,
		}
	}
}

func login_response() func(c *gin.Context, token *core.Token) {
	return func(c *gin.Context, token *core.Token) {
		c.JSON(http.StatusOK, gin.H{
			"code":          http.StatusOK,
			"access_token":  token.AccessToken,
			"token_type":    token.TokenType,
			"refresh_token": token.RefreshToken,
			"expires_at":    token.ExpiresAt,
		})
	}
}

func authenticator() func(c *gin.Context) (any, error) {
	return func(c *gin.Context) (any, error) {
		return nil, g_jwt.ErrMissingLoginValues
	}
}

func authorizer() func(c *gin.Context, data any) bool {
	return func(c *gin.Context, data any) bool {
		_, ok := data.(*User)
		return ok
	}
}

func unauthorized() func(c *gin.Context, code int, message string) {
	return func(c *gin.Context, code int, message string) {
		c.JSON(code, gin.H{
			"code":    code,
			"message": message,
		})
	}
}

func logout_response(rds *Redis_data) func(c *gin.Context) {
	return func(c *gin.Context) {
		claims := g_jwt.ExtractClaims(c)
		raw_exp, ok := claims[D_JWT_exp].(float64)
		if !ok {
			slog.Error("JWT missing exp field")
			c.JSON(400, gin.H{"Error:": " retrieving claims from jwt"})
			return
		}
		token := g_jwt.GetToken(c)
		expires_at := time.Unix(int64(raw_exp), 0)
		remaining := time.Until(expires_at)
		if remaining > 0 {
			remaining += rds.Margin_time
			err := rds.Add_token(token, remaining)
			if err != nil {
				slog.Error("Error Adding token to redis db")
				c.JSON(500, gin.H{"error": "logout failed, please try again"})
				return
			}
		}
		c.JSON(200, gin.H{"message": "logged out"})
	}
}

func handleNoRoute() func(c *gin.Context) {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code":    http.StatusNotFound,
			"message": "Page not found",
		})
	}
}
