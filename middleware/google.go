package middleware

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"emaildrafter/internal/library"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Google OAuth2 Configuration
var (
	config *oauth2.Config
)

// InitializeOAuth initializes the OAuth2 configuration using environment variables
func InitializeOAuth() error {
	clientID := env.GetAsString("GOOGLE_CLIENT_ID")
	clientSecret := env.GetAsString("GOOGLE_CLIENT_SECRET")
	redirectURI := env.GetAsString("GOOGLE_REDIRECT_URI")

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return fmt.Errorf("missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or GOOGLE_REDIRECT_URI")
	}

	config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"email", "profile", "https://www.googleapis.com/auth/gmail.compose", "https://www.googleapis.com/auth/gmail.readonly"},
		Endpoint:     google.Endpoint,
	}

	return nil
}

// generateStateOauthCookie generates a random state and sets it in a cookie
func generateStateOauthCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Printf("Error generating random state: %v", err)
		return ""
	}
	state := base64.URLEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
	return state
}

// LoginHandler handles the Google OAuth2 login
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure OAuth is initialized before using config
	if err := InitializeOAuth(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to initialize OAuth: %v", err), http.StatusInternalServerError)
		return
	}
	oauthState := generateStateOauthCookie(w)
	if oauthState == "" {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	url := config.AuthCodeURL(oauthState, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

// CallbackHandler handles the Google OAuth2 callback
func CallbackHandler(w http.ResponseWriter, r *http.Request, queries *store.Queries) {
	if err := InitializeOAuth(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to initialize OAuth: %v", err), http.StatusInternalServerError)
		return
	}

	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		http.Error(w, "Failed to get state cookie", http.StatusBadRequest)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	token, err := config.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		http.Error(w, "Failed to exchange authorization code for token", http.StatusInternalServerError)
		return
	}

	userInfo, err := getUserInfo(r.Context(), token)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get user info: %v", err), http.StatusInternalServerError)
		return
	}

	err = handleUser(r.Context(), queries, userInfo, token)
	if err != nil {
		log.Printf("Error handling user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create a cookie to store the user's login status
	cookie := &http.Cookie{
		Name:     "loggedIn",
		Value:    "true", // Set to "true" to indicate logged in
		Path:     "/",
		HttpOnly: true,                      // Prevent JavaScript access
		Secure:   true,                      // Only send over HTTPS
		SameSite: http.SameSiteLaxMode,      // Restrict to same-site requests
		MaxAge:   3600,                      // Expire in 60 minutes
		Domain:   env.GetAsString("DOMAIN"), // Allow access from subdomains
	}

	// Get the Google ID from the user info
	googleID, ok := userInfo["sub"].(string)
	if !ok {
		log.Printf("Error getting Google ID from user info: %v", userInfo)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set the Google ID as the cookie value
	cookie.Value = googleID

	// Set the cookie
	http.SetCookie(w, cookie)
	// Redirect to the home page or a protected route
	http.Redirect(w, r, "/", http.StatusFound)
}

func getUserInfo(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := config.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}

func handleUser(ctx context.Context, queries *store.Queries, userInfo map[string]interface{}, token *oauth2.Token) error {
	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	googleID, _ := userInfo["sub"].(string)
	displayName, _ := userInfo["given_name"].(string)
	refreshToken := token.RefreshToken
	accessToken := token.AccessToken
	expiry := token.Expiry
	tokenType := token.TokenType
	var user store.User

	if email == "" || name == "" || googleID == "" {
		return fmt.Errorf("missing required user info")
	}
	user, err := queries.GetUserByGoogleID(ctx, googleID)
	if err != nil {
		// User doesn't exist, create a new one
		u, err := queries.CreateUser(ctx, store.CreateUserParams{
			GoogleID:    googleID,
			Name:        name,
			Email:       email,
			DisplayName: displayName,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
		// insert Token
		_, err = queries.InsertTokenByUserID(ctx, store.InsertTokenByUserIDParams{
			ID: u.ID,
			Accesstoken: sql.NullString{
				String: accessToken,
				Valid:  true,
			},
			Refreshtoken: sql.NullString{
				String: refreshToken,
				Valid:  true},
			Expiry: sql.NullTime{
				Time:  expiry,
				Valid: true,
			},
			Tokentype: sql.NullString{
				String: tokenType,
				Valid:  true,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to insert token: %w", err)
		}
		user = u
	}
	library.GmailCompose(token, user)

	return nil
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request, user_id uuid.UUID, q store.Queries) (err error) {
	// 1. Retrieve refresh token from storage
	refreshToken, err := q.GetRefreshTokenByUserId(r.Context(), user_id) // Replace with your logic for getting user ID
	if err != nil {
		// Handle error, e.g., user not found or no refresh token stored
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// 2. Create a new token source with the refresh token
	tokenSource := config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: refreshToken.String,
	})

	// 3. Exchange refresh token for new access token
	newToken, err := tokenSource.Token()
	if err != nil {
		// Handle error, e.g., invalid refresh token or API rate limits
		http.Error(w, "Failed to refresh token", http.StatusInternalServerError)
		return
	}

	// 4. Store new access and refresh tokens (optional)
	// Depending on your security strategy, you may choose to update the stored refresh token
	// or generate a new one here. Implement logic based on your requirements.

	err = q.InsertAccessTokenByUserId(r.Context(), store.InsertAccessTokenByUserIdParams{
		Accesstoken: sql.NullString{
			String: newToken.AccessToken,
			Valid:  true,
		},
		ID: user_id,
	})

	if err != nil {
		log.Println(err)
	}

	err = q.InsertRefreshTokenByUserId(r.Context(), store.InsertRefreshTokenByUserIdParams{
		Refreshtoken: sql.NullString{
			String: newToken.RefreshToken,
			Valid:  true,
		},
		ID: user_id,
	})

	if err != nil {
		log.Println(err)
	}

	// 5. Return new access token to client
	json.NewEncoder(w).Encode(newToken.AccessToken)
	return nil
}

// GenerateKey generates a random key for encryption
// The salt comes from the .env file.
func GenerateKey(salt string) ([]byte, error) {
	key := []byte(salt) // 32 bytes for AES-256
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// EncryptToken encrypts a token using AES-256 in CBC mode
func EncryptToken(token, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate a random initialization vector (IV)
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create a cipher
	stream := cipher.NewCBCEncrypter(block, iv)

	// Pad the token to the block size
	paddedToken := pkcs7Padding(token, block.BlockSize())

	// Encrypt the token
	encryptedToken := make([]byte, len(paddedToken))
	stream.CryptBlocks(encryptedToken, paddedToken) // Use CryptBlocks instead of XORKeyStream

	// Combine IV and encrypted token
	return append(iv, encryptedToken...), nil
}

// DecryptToken decrypts a token using AES-256 in CBC mode
func DecryptToken(encryptedToken, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract IV from the encrypted token
	iv := encryptedToken[:block.BlockSize()]
	encryptedToken = encryptedToken[block.BlockSize():]

	// Create a cipher
	stream := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the token
	decryptedToken := make([]byte, len(encryptedToken))
	stream.CryptBlocks(decryptedToken, encryptedToken) // Use CryptBlocks instead of XORKeyStream

	// Remove padding
	return pkcs7Unpadding(decryptedToken), nil
}

// pkcs7Padding pads a byte slice to a multiple of the block size
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpadding removes padding from a byte slice
func pkcs7Unpadding(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
