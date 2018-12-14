/*
 * Created Date: Monday, November 26th 2018
 * Author: SilenceEnder
 *
 * SafeKey version 1
 */

package keymanager

import (
	"bufio"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	conf "../configs"
	ut "../utils"
)

const VER string = "1"

type SafeKey struct {
	cipher  string // The cipher used to encrypt filesystem
	comment string // Optional for user
	version string // keymanager version
	sign    string // For password check
	key     string // Store base64-encoded key
	try     int    // Password retry lock
}

func (k *SafeKey) KeyGen(cipher string, len int) {
	k.cipher = cipher
	k.version = VER
	var rawKey []byte
	ut.GetRandKey(&rawKey, len)
	var password string
	var err error = errors.New("No password")
	for err != nil {
		password, err = ut.ReadConfirmedPassword()
	}
	k.sign, err = ut.HashPassword(password)
	ut.PanicIfFail(err, "Failed in hashing!")
	safeKey := ut.GetSafeKeyV1(k.sign, password, conf.SALT)
	rawEncyptedKey := ut.AESEncrypt(rawKey, safeKey)
	k.key = b64.StdEncoding.EncodeToString(rawEncyptedKey)
}

func (k *SafeKey) SaveKey(path string) {
	saveFormattedKey(path, k.cipher, k.comment, k.version, k.sign, k.key)
}

func (k *SafeKey) ReadKey(path string) {
	var data []string
	readFormattedKey(path, &data)
	if len(data) != 5 || data[2] != VER {
		panic("Unsupported key!")
	}

	k.cipher = data[0]
	k.comment = data[1]
	k.version = data[2]
	k.sign = data[3]
	k.key = data[4]
	k.try = conf.MAXTRY
}

func (k *SafeKey) GetKey() []byte {
	if k.try == 0 {
		panic("Failed for too many times. Exit.")
	}
	password := ut.ReadPassword("Enter password:")
	k.try -= 1
	if !ut.CheckPasswordHash(password, k.sign) {
		fmt.Println("Wrong key. Try again.")
		return k.GetKey()
	}
	safeKey := ut.GetSafeKeyV1(k.sign, password, conf.SALT)
	rawEncyptedKey, err := b64.StdEncoding.DecodeString(k.key)
	ut.PanicIfFail(err, "Failed to parse key")
	rawDecryptedKey := ut.AESDecrypt(rawEncyptedKey, safeKey)
	return rawDecryptedKey
}

func (k *SafeKey) GetCipher() string {
	return k.cipher
}

func (k *SafeKey) ChangePassword(path string) {
	k.ReadKey(path)
	rawDecryptedKey := k.GetKey()
	var password string
	var err error = errors.New("No password")
	for err != nil {
		password, err = ut.ReadConfirmedNewPassword()
	}
	k.sign, err = ut.HashPassword(password)
	ut.PanicIfFail(err, "Failed in hashing!")
	safeKey := ut.GetSafeKeyV1(k.sign, password, conf.SALT)
	rawEncyptedKey := ut.AESEncrypt(rawDecryptedKey, safeKey)
	k.key = b64.StdEncoding.EncodeToString(rawEncyptedKey)
	k.SaveKey(path)
}

func (k *SafeKey) SetComment(comment string) {
	k.comment = comment
}

func (k *SafeKey) SetVersion(version string) {
	k.version = version
}

func saveFormattedKey(path string, cipher string, comment string, version string, sign string, key string) {
	file, err := os.Create(path)
	ut.PanicIfFail(err, "Failed to create a key file")

	defer file.Close()

	w := bufio.NewWriter(file)
	keyInfo := fmt.Sprintf(`Encryption: %s
Comment: %s
Version: %s
Sign: %s
Key: %s`, cipher, comment, version, sign, key)
	_, err = w.WriteString(keyInfo)
	ut.PanicIfFail(err, "Failed to write a key file")

	w.Flush()
}

func readFormattedKey(path string, data *[]string) {
	file, err := os.Open(path)
	ut.PanicIfFail(err, "Failed to open the key file")
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		*data = append(*data, strings.Split(scanner.Text(), " ")[1])
	}

	err = scanner.Err()
	ut.PanicIfFail(err, "Failed to read the key file")
}
