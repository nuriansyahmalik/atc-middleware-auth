package users

import (
	"github.com/evermos/boilerplate-go/configs"
	"github.com/evermos/boilerplate-go/shared/failure"
	jwtClaims "github.com/evermos/boilerplate-go/shared/jwt"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt"
	"time"
)

type UsersService interface {
	Create(requestFormat UserRequestFormat, userID uuid.UUID) (user Users, err error)
	Login(requestFormat LoginRequestFormat) (user Users, err error)
}

type UsersServiceImpl struct {
	UserRepository UsersRepository
	Config         *configs.Config
}

func ProvideUserServiceImpl(userRepository UsersRepository, config *configs.Config) *UsersServiceImpl {
	return &UsersServiceImpl{UserRepository: userRepository, Config: config}
}

func (u *UsersServiceImpl) Create(requestFormat UserRequestFormat, userID uuid.UUID) (user Users, err error) {
	user, err = user.UsersRequestFormat(requestFormat, userID)
	if err != nil {
		return
	}
	if err != nil {
		return user, failure.BadRequest(err)

	}
	err = u.UserRepository.Create(user)
	if err != nil {
		return
	}
	user.Token, err = u.generateJWT(user)
	if err != nil {
		return
	}
	return
}
func (u *UsersServiceImpl) Login(requestFormat LoginRequestFormat) (user Users, err error) {
	user, err = user.LoginRequestFormat(requestFormat)
	if err != nil {
		return
	}
	user, err = u.UserRepository.ResolveByEmail(user.Email)
	if err != nil {
		return user, failure.BadRequest(err)
	}
	user.Token, err = u.generateJWT(user)
	if err != nil {
		return
	}
	return
}

func (u *UsersServiceImpl) generateJWT(user Users) (string, error) {
	claims := jwtClaims.Claims{
		ID:    user.ID,
		Email: user.Email,
		Role:  user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(u.Config.App.JWTKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
