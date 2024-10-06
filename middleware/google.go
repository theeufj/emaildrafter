package middleware

import (
	"context"
	"crypto/rand"
	"database/sql"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	config *oauth2.Config
)

func InitializeOAuth() error {
	clientID := env.GetAsString("GOOGLE_CLIENT_ID")
	clientSecret := env.GetAsString("GOOGLE_CLIENT_SECRET")
	redirectURI := env.GetAsString("GOOGLE_REDIRECT_URI")

	if clientID == "" || clientSecret == "" || redirectURI == "" {
		return fmt.Errorf("missing required environment variables: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or GOOGLE_REDIRECT_URI")
	}

	log.Printf("OAuth2 Config: ClientID=%s, RedirectURI=%s", clientID, redirectURI)

	config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURI,
		Scopes:       []string{"email", "profile", "https://www.googleapis.com/auth/calendar", "https://www.googleapis.com/auth/gmail.compose", "https://www.googleapis.com/auth/gmail.readonly"},
		Endpoint:     google.Endpoint,
	}

	return nil
}

func generateStateOauthCookie(w http.ResponseWriter) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error generating random state: %w", err)
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
	return state, nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if err := InitializeOAuth(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to initialize OAuth: %v", err), http.StatusInternalServerError)
		return
	}
	oauthState, err := generateStateOauthCookie(w)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	url := config.AuthCodeURL(oauthState, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

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

	if err := handleUser(r.Context(), queries, userInfo, token); err != nil {
		log.Printf("Error handling user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	googleID, ok := userInfo["sub"].(string)
	if !ok {
		log.Printf("Error getting Google ID from user info: %v", userInfo)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	cookie := &http.Cookie{
		Name:     "loggedIn",
		Value:    googleID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
		Domain:   env.GetAsString("DOMAIN"),
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/admin", http.StatusFound)
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

	if email == "" || name == "" || googleID == "" {
		return fmt.Errorf("missing required user info")
	}

	user, err := queries.GetUserByGoogleID(ctx, googleID)
	if err != nil {
		// User doesn't exist, create a new one
		user, err = queries.CreateUser(ctx, store.CreateUserParams{
			GoogleID:    googleID,
			Name:        name,
			Email:       email,
			DisplayName: displayName,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}
	// need to encrypt all my tokens.
	encryptedAccessToken, err := Encrypt(token.AccessToken, os.Getenv("KEY"))
	if err != nil {
		return fmt.Errorf("error encrypting access token: %w", err)
	}
	encryptedRefreshToken, err := Encrypt(token.RefreshToken, os.Getenv("KEY"))
	if err != nil {
		return fmt.Errorf("error encrypting refresh token: %w", err)
	}
	encrtypedTokenType, err := Encrypt(token.TokenType, os.Getenv("KEY"))
	if err != nil {
		return fmt.Errorf("error encrypting token type: %w", err)
	}
	_, err = queries.InsertTokenByUserID(context.TODO(), store.InsertTokenByUserIDParams{
		ID:           user.ID,
		Accesstoken:  sql.NullString{String: encryptedAccessToken, Valid: true},
		Refreshtoken: sql.NullString{String: encryptedRefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: token.Expiry, Valid: true},
		Tokentype:    sql.NullString{String: encrtypedTokenType, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("failed to insert token: %w", err)
	}

	return nil
}

func HandleRefreshToken(userID uuid.UUID, q *store.Queries) (*oauth2.Token, error) {
	if err := InitializeOAuth(); err != nil {
		return nil, fmt.Errorf("error initializing OAuth: %w", err)
	}

	refreshToken, err := q.GetRefreshTokenByUserId(context.TODO(), userID)
	if err != nil {
		return nil, fmt.Errorf("error retrieving refresh token: %w", err)
	}
	decryptedRefreshToken, err := Decrypt(refreshToken.String, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh toke: %s", err)
	}

	tokenSource := config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: decryptedRefreshToken,
	})

	newToken, err := refreshTokenWithRetry(tokenSource)
	if err != nil {
		return nil, fmt.Errorf("error refreshing token: %w", err)
	}

	// need to encrypt all my tokens.
	encryptedAccessToken, err := Encrypt(newToken.AccessToken, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("error encrypting access token: %w", err)
	}
	encryptedRefreshToken, err := Encrypt(newToken.RefreshToken, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("error encrypting refresh token: %w", err)
	}
	encrtypedTokenType, err := Encrypt(newToken.TokenType, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("error encrypting token type: %w", err)
	}
	_, err = q.InsertTokenByUserID(context.TODO(), store.InsertTokenByUserIDParams{
		ID:           userID,
		Accesstoken:  sql.NullString{String: encryptedAccessToken, Valid: true},
		Refreshtoken: sql.NullString{String: encryptedRefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: newToken.Expiry, Valid: true},
		Tokentype:    sql.NullString{String: encrtypedTokenType, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to insert token: %w", err)
	}

	return newToken, nil
}

func refreshTokenWithRetry(tokenSource oauth2.TokenSource) (*oauth2.Token, error) {
	var token *oauth2.Token
	var err error
	for i := 0; i < 3; i++ {
		token, err = tokenSource.Token()
		if err == nil {
			return token, nil
		}
		log.Printf("Error refreshing token (attempt %d): %v", i+1, err)
		time.Sleep(time.Duration(1<<uint(i)) * time.Second)
	}
	return nil, fmt.Errorf("failed to refresh token after 3 attempts: %w", err)
}

// recommend timeslot using gemini. We need to pass the both the booked timeslots and avalaible times to gemeini so it can correctly recommend a timeslot for a meeting
