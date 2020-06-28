package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	random "math/rand"
	"time"

	"github.com/dandelabs/ghostbuster-backend-libs/dandelog"
	"golang.org/x/crypto/pbkdf2"
	//"crypto/sha1"
)

const (
	letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func generateSalt(secret []byte) ([]byte, error) {
	method := "generateSalt:"
	//saltSize := config.Cfg.Crypto.SaltSize
	saltSize := 16
	buf := make([]byte, saltSize, saltSize+sha256.Size)
	_, err := io.ReadFull(rand.Reader, buf)

	if err != nil {
		dandelog.Error.Printf(method+"random read failed: %v", err)
		return nil, err
	}

	hash := sha256.New()
	hash.Write(buf)
	hash.Write(secret)
	return hash.Sum(buf), err
}

//GenerateEncryptPassword is a function that receives a password
//and returns the hash and the salt that will be stored in the database
func GenerateEncryptPassword(strPassword string) (h []byte, s []byte, err error) {
	var passwordHash []byte
	password := []byte(strPassword)
	salt, err := generateSalt(password)
	if err == nil {
		passwordHash = pbkdf2.Key(password, salt /*config.Cfg.Crypto.Iterations*/, 4096 /*config.Cfg.Crypto.KeySize*/, 32, sha256.New)
	}
	return passwordHash, salt, err
}

//ValidatePassword is a function that receives the password the salt and
//the hash and says if this password correspond with the original one
func ValidatePassword(strPassword string, salt []byte, hash []byte, iterations int, keySize int) bool {
	password := []byte(strPassword)
	validatedHash := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
	match := bytes.Equal(hash, validatedHash)
	return match
}

// RandString of length ng
func RandString(n int) string {
	var src = random.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}
