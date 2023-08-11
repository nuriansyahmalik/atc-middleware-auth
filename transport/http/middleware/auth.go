package middleware

import (
	"context"
	"fmt"
	"github.com/evermos/boilerplate-go/configs"
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
	"net/http"
	"strings"

	"github.com/evermos/boilerplate-go/infras"
	jwtClaims "github.com/evermos/boilerplate-go/shared/jwt"
	"github.com/evermos/boilerplate-go/shared/oauth"
	"github.com/evermos/boilerplate-go/transport/http/response"
)

type Authentication struct {
	db *infras.MySQLConn
}

const (
	HeaderAuthorization = "Authorization"
)

func ProvideAuthentication(db *infras.MySQLConn) *Authentication {
	return &Authentication{
		db: db,
	}
}

func (a *Authentication) ValidateToken(tokenString string) (*jwtClaims.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(configs.Get().App.JWTKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %v", err)
	}

	if claims, ok := token.Claims.(*jwtClaims.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("JWT is not valid")
}

func (a *Authentication) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			log.Info().Msg("No authorization header")
			http.Error(w, "Unauthorized: Token missing", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(tokenString, "Bearer ")
		if token == "" {
			log.Info().Msg("Invalid token format")
			http.Error(w, "Unauthorized: Invalid token format", http.StatusUnauthorized)
			return
		}

		claims, err := a.ValidateToken(token)
		if err != nil {
			log.Error().Err(err)
			http.Error(w, "Unauthorized: Token invalid", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authentication) ClientCredential(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Header.Get(HeaderAuthorization)
		token := oauth.New(a.db.Read, oauth.Config{})

		parseToken, err := token.ParseWithAccessToken(accessToken)
		if err != nil {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		if !parseToken.VerifyExpireIn() {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Authentication) ClientCredentialWithQueryParameter(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		token := params.Get("token")
		tokenType := params.Get("token_type")
		accessToken := tokenType + " " + token

		auth := oauth.New(a.db.Read, oauth.Config{})
		parseToken, err := auth.ParseWithAccessToken(accessToken)
		if err != nil {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		if !parseToken.VerifyExpireIn() {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Authentication) Password(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Header.Get(HeaderAuthorization)
		token := oauth.New(a.db.Read, oauth.Config{})

		parseToken, err := token.ParseWithAccessToken(accessToken)
		if err != nil {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		if !parseToken.VerifyExpireIn() {
			response.WithMessage(w, http.StatusUnauthorized, err.Error())
			return
		}

		if !parseToken.VerifyUserLoggedIn() {
			response.WithMessage(w, http.StatusUnauthorized, oauth.ErrorInvalidPassword)
			return
		}

		next.ServeHTTP(w, r)
	})
}
