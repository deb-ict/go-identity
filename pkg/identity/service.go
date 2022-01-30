package identity

type SecretHasher interface {
	VerifySecret(hash string, secret string) error
	HashSecret(secret string) (string, error)
}

type ClientStore interface {
	GetClientById(id string) (*Client, error)
}

type ResourceStore interface {
}

type IdentityService interface {
}
