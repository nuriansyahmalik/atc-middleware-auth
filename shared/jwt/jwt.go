package jwt

import (
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
)

type Claims struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Role  string    `json:"role"`
	jwt.StandardClaims
}

//func GenerateJWT(user users.Users) (string, error) {
//	expTime := time.Now().Add(60 * time.Minute)
//	claims := &Claims{
//		ID:    user.ID,
//		Email: user.Email,
//		Role:  user.Role,
//		StandardClaims: jwt.StandardClaims{
//			ExpiresAt: expTime.Unix(),
//		},
//	}
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
//
//	tokenString, err := token.SignedString(configs.Get().App.JWTKey)
//	return tokenString, err
//}
