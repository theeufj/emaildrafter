package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Encrypt encrypts the input text using AES-CBC encryption
func Encrypt(plaintext, key string) (string, error) {
	keyHash, err := hashKey(key)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return "", err
	}

	// Pad the plaintext
	plaintext = string(PKCS7Padding([]byte(plaintext), aes.BlockSize))

	// Generate a random IV
	iv, err := GenerateRandomBytes(aes.BlockSize)
	if err != nil {
		return "", err
	}

	// Create the CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the padded plaintext
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, []byte(plaintext))

	// Prepend IV to ciphertext
	fullCiphertext := append(iv, ciphertext...)

	// Encode the result as base64

	return base64.StdEncoding.EncodeToString(fullCiphertext), nil
}

// Decrypt decrypts the input text using AES-CBC decryption
func Decrypt(ciphertext, key string) (string, error) {

	// Decode the base64 encoded ciphertext
	fullCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decoding failed: %w", err)
	}

	keyHash, err := hashKey(key)
	if err != nil {
		return "", fmt.Errorf("key hashing failed: %w", err)
	}

	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return "", fmt.Errorf("creating cipher failed: %w", err)
	}

	if len(fullCiphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short: %d < %d", len(fullCiphertext), aes.BlockSize)
	}

	iv := fullCiphertext[:aes.BlockSize]
	ciphertextBytes := fullCiphertext[aes.BlockSize:]

	// Create the CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the ciphertext
	plaintext := make([]byte, len(ciphertextBytes))
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Remove padding
	unpadded, err := PKCS7UnPadding(plaintext)
	if err != nil {
		return "", fmt.Errorf("PKCS7 unpadding failed: %w", err)
	}

	return string(unpadded), nil
}

// PKCS7Padding adds PKCS7 padding to the input slice
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7UnPadding removes PKCS7 padding from the input slice
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}
	unpadding := int(data[length-1])

	if unpadding > length {
		return nil, fmt.Errorf("invalid padding size: %d > %d", unpadding, length)
	}

	return data[:(length - unpadding)], nil
}

// hashKey creates a hashed key using SHA256
func hashKey(key string) ([]byte, error) {
	hash := sha256.Sum256([]byte(key))
	return hash[:], nil
}

// GenerateRandomBytes generates random bytes of the specified length
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := GenerateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}
