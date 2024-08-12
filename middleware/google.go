package middleware

import (
	"context"
	"crypto/rand"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

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
		Scopes:       []string{"email", "profile"},
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

	err = handleUser(r.Context(), queries, userInfo)
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

func handleUser(ctx context.Context, queries *store.Queries, userInfo map[string]interface{}) error {
	email, _ := userInfo["email"].(string)
	name, _ := userInfo["name"].(string)
	googleID, _ := userInfo["sub"].(string)

	if email == "" || name == "" || googleID == "" {
		return fmt.Errorf("missing required user info")
	}
	_, err := queries.GetUserByGoogleID(ctx, googleID)
	if err != nil {
		// User doesn't exist, create a new one
		u, err := queries.CreateUser(ctx, store.CreateUserParams{
			GoogleID: googleID,
			Name:     name,
			Email:    email,
		})
		log.Println(u)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	return nil
}
