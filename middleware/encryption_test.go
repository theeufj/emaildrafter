package middleware

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	originalText := "this_is_a_test_refresh_token_12345"
	key := "your_test_key_here"

	encrypted, err := Encrypt(originalText, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != originalText {
		t.Errorf("Decrypted text does not match original. Got %s, want %s", decrypted, originalText)
	}
}

func TestEncryptionDeterminism(t *testing.T) {
	plaintext := "This is a secret message"
	key := "my-secret-key"

	// Encrypt the same plaintext twice
	ciphertext1, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Verify that the two ciphertexts are different (due to random IV)
	if ciphertext1 == ciphertext2 {
		t.Error("Expected different ciphertexts for the same plaintext due to random IV, but got identical ciphertexts")
	}
}

func TestDecryptionWithWrongKey(t *testing.T) {
	plaintext := "This is a secret message"
	correctKey := "correct-secret-key"
	wrongKey := "wrong-secret-key"

	// Encrypt with the correct key
	ciphertext, err := Encrypt(plaintext, correctKey)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt to decrypt with the wrong key
	_, err = Decrypt(ciphertext, wrongKey)
	if err == nil {
		t.Error("Expected decryption with wrong key to fail, but it succeeded")
	}
}

func TestPaddingFunctions(t *testing.T) {
	testCases := []struct {
		name      string
		input     []byte
		blockSize int
	}{
		{"Empty input", []byte{}, 16},
		{"Input smaller than block size", []byte{1, 2, 3}, 16},
		{"Input equal to block size", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 16},
		{"Input larger than block size", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}, 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			padded := PKCS7Padding(tc.input, tc.blockSize)
			if len(padded)%tc.blockSize != 0 {
				t.Errorf("PKCS7Padding failed: padded length %d is not a multiple of block size %d", len(padded), tc.blockSize)
			}

			unpadded, err := PKCS7UnPadding(padded)
			if err != nil {
				t.Errorf("PKCS7UnPadding failed: %v", err)
			}

			if string(unpadded) != string(tc.input) {
				t.Errorf("PKCS7UnPadding failed: expected %v, got %v", tc.input, unpadded)
			}
		})
	}
}

func TestEncryptDecryptRefreshToken(t *testing.T) {
	originalToken := "1//0gdt6jliPmNfSCgYIARAAGBASNwF-L9Ir17WBJW61PaPbi7b_Xt8KyZspBnd7K31r6nbYNbrycULD5d-trGA_YqV_3yfFFmSClaI"
	key := "passphrasewhichneedstobe32bytes!"

	encrypted, err := Encrypt(originalToken, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != originalToken {
		t.Errorf("Decrypted token does not match original. Got %s, want %s", decrypted, originalToken)
	}
}
