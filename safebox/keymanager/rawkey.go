package keymanager

import (
	b64 "encoding/base64"
	"io/ioutil"
	"os"

	ut "../utils"
)

type RawKey struct {
	cipher string
	key    string
}

func (k *RawKey) KeyGen(cipher string, len int) {
	k.cipher = cipher
	var rawKey []byte
	ut.GetRandKey(&rawKey, len)
	k.key = b64.StdEncoding.EncodeToString(rawKey)
}

func (k *RawKey) SaveKey(path string) {
	if len(k.key) == 0 {
		panic("Key is empty")
	}
	permissions := os.FileMode(0644)
	err := ioutil.WriteFile(path, []byte(k.key), permissions)
	ut.PanicIfFail(err, "Failed when saving key")
}

func (k *RawKey) ReadKey(path string) {
	data, err := ioutil.ReadFile(path)
	ut.PanicIfFail(err, "Failed when reading key")
	k.key = string(data)
}

func (k *RawKey) GetKey() []byte {
	rawKey, _ := b64.URLEncoding.DecodeString(k.key)
	return rawKey
}

func (k *RawKey) GetCipher() string {
	return k.cipher
}

func (k *RawKey) ChangePassword(path string) {
	panic("RawKey.ChangePassword() Not implemented!")
}
