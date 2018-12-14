package keymanager

type KeyManager interface {
	KeyGen(cipher string, len int)
	SaveKey(path string)
	ReadKey(path string) // Read base64-encoded key from file into key struct.
	GetKey() []byte      // Decode and decrypt key and return raw key in byte array. Password may be required.
	GetCipher() string
	ChangePassword(path string)
}

type KeyinfoManager interface {
	SetComment(comment string)
	SetVersion(version string)
}
