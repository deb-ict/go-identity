package identity

type User struct {
	Id                 string
	NormalizedUsername string
	NormalizedEmail    string
	Username           string
	Password           string
	Email              string
	EmailVerified      bool
	IsEnabled          bool
}
