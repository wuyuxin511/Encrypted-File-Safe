package utils

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	conf "../configs"

	homedir "github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

type errorString struct {
	s string
}

func (e *errorString) Error() string {
	return e.s
}

func PrintIfFail(err error, info string) {
	if err != nil {
		fmt.Println(info)
	}
}

func PanicIfFail(err error, info string) {
	if err != nil {
		fmt.Println(info)
		panic(err)
	}
}

func GetHomeDir() string {
	dir, err := homedir.Dir()
	if err != nil {
		fmt.Println("Failed to get home path!")
		return "/"
	}
	dir += "/"
	return dir
}

func GetRandKey(key *[]byte, len int) {
	*key = make([]byte, len)
	_, err := rand.Read(*key)
	PanicIfFail(err, "Failed when generating key")
}

func ReadUserInput(hint string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(hint + ": ")
	input, err := reader.ReadString('\n')
	PrintIfFail(err, "Invalid input!")
	input = strings.TrimSpace(input)
	return input
}

func ReadUserInputWithDefault(hint string, defau string) string {
	input := ReadUserInput(fmt.Sprintf("%s(default: %s)", hint, defau))
	if len(input) == 0 {
		return defau
	}
	return input
}

func ReadPassword(hint string) string {
	fmt.Print(hint)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	PanicIfFail(err, "Failed to read password")
	password := strings.TrimSpace(string(bytePassword))
	fmt.Println()

	return password
}

func ReadConfirmedPassword() (string, error) {
	pwd := ""
	for len(pwd) < conf.MIN_PWD_LEN {
		pwd = ReadPassword(fmt.Sprintf("Enter your password(At least %d words):", conf.MIN_PWD_LEN))
	}
	pwd_confirm := ReadPassword("Confirm your password:")
	if pwd != pwd_confirm {
		fmt.Println("Password mismatch. Try again.")
		return "", &errorString{"Confirm failed"}
	}
	return pwd, nil
}

func ReadConfirmedNewPassword() (string, error) {
	pwd := ""
	for len(pwd) < conf.MIN_PWD_LEN {
		pwd = ReadPassword(fmt.Sprintf("Enter your new password(At least %d words):", conf.MIN_PWD_LEN))
	}
	pwd_confirm := ReadPassword("Confirm your new password:")
	if pwd != pwd_confirm {
		fmt.Println("Password mismatch. Try again.")
		return "", &errorString{"Confirm failed"}
	}
	return pwd, nil
}

// Uses bcrypt to gene a unique hash each time even for the same text
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), conf.HASH_COMPLEXITY)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func MD5Hash(key string) []byte {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hasher.Sum(nil)
}

// This func generate the final key to encrypt raw key
func GetSafeKeyV1(salt1, password, salt2 string) []byte {
	return MD5Hash(salt1 + hex.EncodeToString(MD5Hash(password)) + salt2)
}

// AES GCM mode for confidentiality and integrity
func AESEncrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, err := cipher.NewGCM(block)
	PanicIfFail(err, "Encryption failed")
	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	PanicIfFail(err, "Encryption failed")
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func AESDecrypt(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	PanicIfFail(err, "Decryption failed")
	gcm, err := cipher.NewGCM(block)
	PanicIfFail(err, "Decryption failed")
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	PanicIfFail(err, "Decryption failed")
	return plaintext
}
