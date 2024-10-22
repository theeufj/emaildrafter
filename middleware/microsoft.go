package middleware

import (
	"context"
	"crypto/rand"
	"database/sql"
	"emaildrafter/database/store"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/sessions"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// ClientConfig holds the configuration for MicrosoftClient
type ClientConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Store        *sessions.CookieStore
}

// MicrosoftClient handles OAuth interactions
type MicrosoftClient struct {
	config ClientConfig
	db     store.Queries
}

// TokenResponse represents the OAuth token response from Microsoft
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

// UserInfo represents basic Microsoft user information
type UserInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Email       string `json:"mail"`
}

// IDTokenClaims represents the claims in the ID token
type IDTokenClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Sub   string `json:"sub"`
	jwt.StandardClaims
}

// NewMicrosoftClient creates a new instance of MicrosoftClient
func NewMicrosoftClient(db store.Queries) (*MicrosoftClient, error) {
	config := ClientConfig{
		TenantID:     os.Getenv("TENANT_ID"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
	}

	if config.TenantID == "" || config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("invalid configuration: tenant ID, client ID, and client secret are required")
	}

	// Create session store
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to create session key: %w", err)
	}
	config.Store = sessions.NewCookieStore(key)

	return &MicrosoftClient{
		config: config,
		db:     db,
	}, nil
}

// LoginHandlerMicrosoft initiates the OAuth flow
func (mc *MicrosoftClient) LoginHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	state := mc.generateState()

	// Store state in cookie
	cookie := &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)

	// Build authorization URL
	scopes := url.QueryEscape("openid email profile User.Read offline_access")
	authURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?"+
			"client_id=%s"+
			"&response_type=code"+
			"&redirect_uri=%s"+
			"&scope=%s"+
			"&state=%s",
		mc.config.TenantID,
		mc.config.ClientID,
		url.QueryEscape(mc.config.RedirectURL),
		scopes,
		state,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// CallbackHandlerMicrosoft handles the OAuth callback
func (mc *MicrosoftClient) CallbackHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	// Verify state
	oauthState, err := r.Cookie("oauthstate")
	if err != nil || r.FormValue("state") != oauthState.Value {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, idTokenClaims, err := mc.exchangeCodeForToken(code)
	if err != nil {
		log.Printf("Error exchanging code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	// Create user info from ID token claims
	userInfo := &UserInfo{
		ID:          idTokenClaims.Sub,
		DisplayName: idTokenClaims.Name,
		Email:       idTokenClaims.Email,
	}

	// Handle user creation/update
	if err := mc.handleUser(r.Context(), userInfo, token); err != nil {
		http.Error(w, "Failed to handle user", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	cookie := &http.Cookie{
		Name:     "loggedIn",
		Value:    userInfo.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/admin", http.StatusFound)
}

// Helper functions
func (mc *MicrosoftClient) generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (mc *MicrosoftClient) exchangeCodeForToken(code string) (*TokenResponse, *IDTokenClaims, error) {
	data := url.Values{}
	data.Set("client_id", mc.config.ClientID)
	data.Set("client_secret", mc.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", mc.config.RedirectURL)

	resp, err := http.PostForm(
		fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", mc.config.TenantID),
		data,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// Decode ID token
	claims, err := decodeIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode ID token: %w", err)
	}

	return &tokenResp, claims, nil
}

func decodeIDToken(idToken string) (*IDTokenClaims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	payload, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &claims, nil
}

func (mc *MicrosoftClient) handleUser(ctx context.Context, userInfo *UserInfo, token *TokenResponse) error {
	// Check if user exists
	user, err := mc.db.GetUserByMicrosoftID(ctx, sql.NullString{String: userInfo.ID, Valid: true})
	if err != nil {
		// Create new user if not found
		user, err = mc.db.CreateUserWithMicrosoftID(ctx, store.CreateUserWithMicrosoftIDParams{
			MicrosoftID: sql.NullString{String: userInfo.ID, Valid: true},
			Name:        userInfo.DisplayName,
			Email:       userInfo.Email,
			DisplayName: userInfo.DisplayName,
		})
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Store tokens
	expiryTime := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	_, err = mc.db.InsertTokenByUserID(ctx, store.InsertTokenByUserIDParams{
		ID:           user.ID,
		Accesstoken:  sql.NullString{String: token.AccessToken, Valid: true},
		Refreshtoken: sql.NullString{String: token.RefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: expiryTime, Valid: true},
		Tokentype:    sql.NullString{String: token.TokenType, Valid: true},
	})

	return err
}

func (mc *MicrosoftClient) GetAndLogUserEmails(ctx context.Context, microsoftID string) error {
	_, err := mc.db.GetUserByMicrosoftID(ctx, sql.NullString{String: microsoftID, Valid: true})
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	log.Println("tenantID", mc.config.TenantID)

	// Initialize the Microsoft Graph client
	cred, err := azidentity.NewClientSecretCredential(mc.config.TenantID, mc.config.ClientID, mc.config.ClientSecret, nil)
	if err != nil {
		return fmt.Errorf("failed to create credential: %w", err)
	}

	log.Println("cred", cred)
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		return fmt.Errorf("failed to create Graph client: %w", err)
	}

	me, err := graphClient.Me().Get(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("failed to get user info: %w", err)
	}
	log.Println("me", me)
	return nil
}
