package tenancy

import (
	"context"
	"errors"
	"net/http"
)

type ContextKey string

const (
	TenantContextKey ContextKey = "tenant"
)

var (
	ErrTenantNotFound error = errors.New("tenant not found")
)

type TenantContext interface {
	GetId() string
}

type tenantContext struct {
	Id string
}

func NewContext(id string) TenantContext {
	return &tenantContext{
		Id: id,
	}
}

func GetContext(ctx context.Context) (*TenantContext, error) {
	val := ctx.Value(TenantContextKey)
	if val == nil {
		return nil, ErrTenantNotFound
	}
	tenant, ok := val.(*TenantContext)
	if !ok {
		return nil, ErrTenantNotFound
	}
	return tenant, nil
}

func SetContext(ctx context.Context, tenant *TenantContext) context.Context {
	return context.WithValue(ctx, TenantContextKey, tenant)
}

func GetHttpContext(r *http.Request) (*TenantContext, error) {
	return GetContext(r.Context())
}

func SetHttpContext(r *http.Request, tenant *TenantContext) *http.Request {
	return r.WithContext(SetContext(r.Context(), tenant))
}

func (c *tenantContext) GetId() string {
	return c.Id
}
