package auth

type Auth interface {
	uidAuth() int
	passwdAuth() int
	getKey() string
}
