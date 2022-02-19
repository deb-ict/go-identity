package identity

type UserStore interface {
	GetUserByUserName(userName string) (*User, error)
}

type User struct {
	Username string
	Password string
	Email    string
}
