package usecase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Gorapeflutter/gorape/pkg/entity/model"
	"github.com/Gorapeflutter/gorape/pkg/server/repository"
)

type Project interface {
	Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error)
	AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error)
	RequireProject(ctx context.Context, a model.AuthContext, min model.Role) error
}

type projectUsecase struct {
	store  *repository.Store
	tokens repository.TokenValidator
}

func NewProject(store *repository.Store, tokens repository.TokenValidator) Project {
	return &projectUsecase{store: store, tokens: tokens}
}

func (rcvr *projectUsecase) Authenticate(ctx context.Context, projectID, token string) (model.AuthContext, error) {
	id, e := repository.ParseUUID(projectID)
	if e != nil {
		return model.AuthContext{}, e
	}
	p, e := rcvr.store.Project(ctx, id)
	if e != nil {
		return model.AuthContext{}, e
	}
	claims, e := rcvr.tokens.Validate(ctx, p, token)
	if e != nil {
		return model.AuthContext{}, e
	}
	principal, e := rcvr.store.EnsurePrincipal(ctx, p, claims.Issuer, claims.Subject)
	if e != nil {
		return model.AuthContext{}, e
	}
	return model.AuthContext{Project: p, Principal: principal, Claims: claims}, nil
}

func (rcvr *projectUsecase) AuthenticateIssuer(ctx context.Context, token string) (model.AuthContext, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return model.AuthContext{}, errors.New("malformed access token")
	}
	b, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return model.AuthContext{}, errors.New("malformed access token")
	}
	var hint struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(b, &hint) != nil || hint.Issuer == "" {
		return model.AuthContext{}, errors.New("access token issuer is missing")
	}
	p, e := rcvr.store.ProjectByIssuer(ctx, hint.Issuer)
	if e != nil {
		return model.AuthContext{}, e
	}
	return rcvr.Authenticate(ctx, p.ID.String(), token)
}

func (rcvr *projectUsecase) RequireProject(ctx context.Context, a model.AuthContext, min model.Role) error {
	r, e := rcvr.store.ProjectRole(ctx, a.Project.ID, a.Principal.ID)
	if e != nil || r.Rank() < min.Rank() {
		return ErrForbidden
	}
	return nil
}
