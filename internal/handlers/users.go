package handlers

import (
	"encoding/json"
	"github.com/evermos/boilerplate-go/internal/domain/users"
	"github.com/evermos/boilerplate-go/shared"
	"github.com/evermos/boilerplate-go/shared/failure"
	"github.com/evermos/boilerplate-go/shared/jwt"
	"github.com/evermos/boilerplate-go/shared/logger"
	"github.com/evermos/boilerplate-go/transport/http/middleware"
	"github.com/evermos/boilerplate-go/transport/http/response"
	"github.com/go-chi/chi"
	"github.com/gofrs/uuid"
	"net/http"
)

type UsersHandler struct {
	UsersService   users.UsersService
	AuthMiddleware *middleware.Authentication
}

// ProvideUsersHandler is the provider for this handler.
func ProvideUsersHandler(usersService users.UsersService, authMiddleware *middleware.Authentication) UsersHandler {
	return UsersHandler{
		UsersService:   usersService,
		AuthMiddleware: authMiddleware,
	}
}
func (h *UsersHandler) Router(r chi.Router) {
	r.Route("/users", func(r chi.Router) {
		r.Use(h.AuthMiddleware.AuthMiddleware)
		r.Post("/", h.CreateUser)
		r.Post("/login", h.Login)
		r.Get("/validate-auth", h.ValidateUsers)
	})
}

// CreateUser create a new user
// @Summary Create a new user
// @Description this endpoint create a new user
// @Tags user/user
// @Security JWTAuthentication
// @Param user body users.UserRequestFormat true "The User to be created."
// @Produce json
// @Success 201 {object} response.Base{data=users.UserResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 409 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/user/ [post]
func (h *UsersHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat users.UserRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}
	userID, err := uuid.NewV4()
	if err != nil {
		logger.ErrorWithStack(err)
		return
	}
	user, err := h.UsersService.Create(requestFormat, userID)
	if err != nil {
		response.WithError(w, err)
		return
	}
	response.WithJSON(w, http.StatusCreated, user)
}

// Login logins a new user
// @Summary Login a new user
// @Description this endpoint create a new user
// @Tags user/user
// @Security JWTAuthentication
// @Param user body users.LoginRequestFormat true "The user to be login."
// @Produce json
// @Success 200 {object} response.Base{data=users.UserResponseFormat}
// @Failure 400 {object} response.Base
// @Failure 409 {object} response.Base
// @Failure 500 {object} response.Base
// @Router /v1/user/login [post]
func (h *UsersHandler) Login(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var requestFormat users.LoginRequestFormat
	err := decoder.Decode(&requestFormat)
	if err != nil {
		response.WithError(w, failure.BadRequest(err))
		return
	}
	err = shared.GetValidator().Struct(requestFormat)
	if err != nil {
		logger.ErrorWithStack(err)
		response.WithError(w, failure.BadRequest(err))
		return
	}

	foo, err := h.UsersService.Login(requestFormat)
	if err != nil {
		logger.ErrorWithStack(err)
		response.WithError(w, err)
		return
	}

	response.WithJSON(w, http.StatusOK, foo)
}

func (h *UsersHandler) ValidateUsers(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value("claims").(*jwt.Claims)
	if !ok || claims == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	response.WithJSON(w, http.StatusOK, claims)
}
