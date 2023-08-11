package users

import (
	"encoding/json"
	"github.com/evermos/boilerplate-go/shared/nuuid"
	"github.com/gofrs/uuid"
	"github.com/guregu/null"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type Users struct {
	ID        uuid.UUID   `db:"user_id"`
	Username  string      `db:"username"`
	Email     string      `db:"email"`
	Password  string      `db:"password"`
	Role      string      `db:"role"`
	Token     string      `db:"-"`
	CreatedAt time.Time   `db:"created_at"`
	CreatedBy uuid.UUID   `db:"created_by"`
	UpdatedAt null.Time   `db:"updated_at"`
	UpdatedBy nuuid.NUUID `db:"updated_by"`
	DeletedAt null.Time   `db:"deleted_at"`
	DeletedBy nuuid.NUUID `db:"deleted_by"`
}

type (
	UserRequestFormat struct {
		Username string `json:"username"  validate:"required"`
		Email    string `json:"email"  validate:"required"`
		Password string `json:"password"  validate:"required"`
		Role     string `json:"role"  validate:"required"`
	}
	LoginRequestFormat struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}
	UserResponseFormat struct {
		ID       uuid.UUID `json:"ID,omitempty"`
		Username string    `json:"username,omitempty"`
		Email    string    `json:"email,omitempty"`
		Password string    `json:"password,omitempty"`
		Role     string    `json:"role,omitempty"`
		Token    string    `json:"token"`
	}
)

func (u Users) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.ToResponseFormat())
}

func (u *Users) UsersRequestFormat(req UserRequestFormat, id uuid.UUID) (user Users, err error) {
	id, _ = uuid.NewV4()
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return Users{}, err
	}
	user = Users{
		ID:       id,
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		Role:     req.Role,
	}
	return
}

func (u *Users) ToResponseFormat() UserResponseFormat {
	return UserResponseFormat{
		ID:       u.ID,
		Username: u.Username,
		Email:    u.Email,
		Role:     u.Role,
		Token:    u.Token,
	}
}

func (u *Users) LoginRequestFormat(req LoginRequestFormat) (user Users, err error) {
	user = Users{
		Email:    req.Email,
		Password: req.Password,
	}
	return
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}
