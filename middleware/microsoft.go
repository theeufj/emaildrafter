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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	graphusers "github.com/microsoftgraph/msgraph-sdk-go/users"
)

// ClientConfig holds the configuration for MicrosoftClient
type ClientConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
	Store        *sessions.CookieStore // Add this line
}

// MicrosoftClient handles interactions with Microsoft Graph API
type MicrosoftClient struct {
	graphClient *msgraphsdk.GraphServiceClient
	db          store.Queries
	config      ClientConfig
}

// NewMicrosoftClient creates a new instance of MicrosoftClient
func NewMicrosoftClient(db store.Queries) (*MicrosoftClient, error) {
	// this should get the config params from the .env file
	// new config.
	config := ClientConfig{
		TenantID:     os.Getenv("TENANT_ID"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
	if config.TenantID == "" || config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("invalid configuration: tenant ID, client ID, and client secret are required")
	}

	cred, err := azidentity.NewClientSecretCredential(
		config.TenantID,
		config.ClientID,
		config.ClientSecret,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential: %w", err)
	}

	if len(config.Scopes) == 0 {
		config.Scopes = []string{"https://graph.microsoft.com/.default"}
	}

	client, err := msgraphsdk.NewGraphServiceClientWithCredentials(cred, config.Scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to create graph client: %w", err)
	}

	key := make([]byte, 32)
	rand.Read(key)
	config.Store = sessions.NewCookieStore(key) // Add this line

	return &MicrosoftClient{
		graphClient: client,
		db:          db,
		config:      config,
	}, nil
}

// Email represents a simplified email message structure
type Email struct {
	ID            string
	Subject       string
	Body          string
	From          string
	To            []string
	ReceivedAt    time.Time
	IsRead        bool
	HasAttachment bool
}

// CalendarEvent represents a simplified calendar event structure
type CalendarEvent struct {
	ID        string
	Subject   string
	Body      string
	Start     string
	End       string
	Location  string
	Attendees []string
	IsOnline  bool
}

// GetEmails retrieves emails for a user with optional filtering
func (mc *MicrosoftClient) GetEmails(ctx context.Context, userID string, options *graphusers.ItemMessagesRequestBuilderGetRequestConfiguration) ([]Email, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	messages, err := mc.graphClient.Users().ByUserId(userID).Messages().Get(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get emails: %w", err)
	}

	var emails []Email
	for _, msg := range messages.GetValue() {
		email := Email{
			ID:            *msg.GetId(),
			Subject:       *msg.GetSubject(),
			Body:          *msg.GetBody().GetContent(),
			From:          *msg.GetFrom().GetEmailAddress().GetAddress(),
			ReceivedAt:    *msg.GetReceivedDateTime(),
			IsRead:        *msg.GetIsRead(),
			HasAttachment: len(msg.GetAttachments()) > 0,
		}

		toRecipients := msg.GetToRecipients()
		email.To = make([]string, len(toRecipients))
		for i, recipient := range toRecipients {
			email.To[i] = *recipient.GetEmailAddress().GetAddress()
		}

		emails = append(emails, email)
	}

	return emails, nil
}

// GetCalendarEvents retrieves calendar events for a user within a time range
func (mc *MicrosoftClient) GetCalendarEvents(ctx context.Context, userID string, startTime, endTime time.Time) ([]CalendarEvent, error) {
	if userID == "" {
		return nil, fmt.Errorf("userID cannot be empty")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	filter := fmt.Sprintf("start/dateTime ge '%s' and end/dateTime le '%s'", startTime.Format(time.RFC3339), endTime.Format(time.RFC3339))
	options := &graphusers.ItemCalendarEventsRequestBuilderGetRequestConfiguration{
		QueryParameters: &graphusers.ItemCalendarEventsRequestBuilderGetQueryParameters{
			Select: []string{"subject", "body", "start", "end", "location", "attendees"},
			Filter: &filter,
		},
	}

	events, err := mc.graphClient.Users().ByUserId(userID).Calendar().Events().Get(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get calendar events: %w", err)
	}

	var calendarEvents []CalendarEvent
	for _, event := range events.GetValue() {
		calEvent := CalendarEvent{
			ID:       *event.GetId(),
			Subject:  *event.GetSubject(),
			Body:     *event.GetBody().GetContent(),
			Start:    *event.GetStart().GetDateTime(),
			End:      *event.GetEnd().GetDateTime(),
			Location: *event.GetLocation().GetDisplayName(),
			IsOnline: *event.GetIsOnlineMeeting(),
		}

		attendees := event.GetAttendees()
		calEvent.Attendees = make([]string, len(attendees))
		for i, attendee := range attendees {
			calEvent.Attendees[i] = *attendee.GetEmailAddress().GetAddress()
		}

		calendarEvents = append(calendarEvents, calEvent)
	}

	return calendarEvents, nil
}

// DraftResponse represents an email response to be sent
type DraftResponseMicrosoft struct {
	Content      string
	IsHTML       bool
	Recipients   []string
	CCRecipients []string
	Attachments  []Attachment
}

// Attachment represents an email attachment
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// SendDraftResponse sends a reply to an existing email
func (mc *MicrosoftClient) SendDraftResponse(ctx context.Context, userID, emailID string, draft DraftResponseMicrosoft) error {
	if userID == "" || emailID == "" || draft.Content == "" {
		return fmt.Errorf("invalid input: userID, emailID, and content cannot be empty")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	message := graphmodels.NewMessage()
	body := graphmodels.NewItemBody()

	contentType := graphmodels.TEXT_BODYTYPE
	if draft.IsHTML {
		contentType = graphmodels.HTML_BODYTYPE
	}

	body.SetContent(&draft.Content)
	body.SetContentType(&contentType)
	message.SetBody(body)

	// Add recipients if specified
	if len(draft.Recipients) > 0 {
		recipients := make([]graphmodels.Recipientable, len(draft.Recipients))
		for i, email := range draft.Recipients {
			recipient := graphmodels.NewRecipient()
			emailAddress := graphmodels.NewEmailAddress()
			emailAddress.SetAddress(&email)
			recipient.SetEmailAddress(emailAddress)
			recipients[i] = recipient
		}
		message.SetToRecipients(recipients)
	}

	// Add CC recipients if specified
	if len(draft.CCRecipients) > 0 {
		ccRecipients := make([]graphmodels.Recipientable, len(draft.CCRecipients))
		for i, email := range draft.CCRecipients {
			recipient := graphmodels.NewRecipient()
			emailAddress := graphmodels.NewEmailAddress()
			emailAddress.SetAddress(&email)
			recipient.SetEmailAddress(emailAddress)
			ccRecipients[i] = recipient
		}
		message.SetCcRecipients(ccRecipients)
	}

	requestBody := graphusers.NewItemMessagesItemReplyPostRequestBody()
	requestBody.SetMessage(message)

	err := mc.graphClient.Users().ByUserId(userID).Messages().ByMessageId(emailID).Reply().Post(ctx, requestBody, nil)
	if err != nil {
		return fmt.Errorf("failed to send draft response: %w", err)
	}

	return nil
}

// RefreshToken refreshes the access token using the stored refresh token
func (mc *MicrosoftClient) RefreshToken(ctx context.Context, userID string) error {
	// Implementation would depend on your token storage and refresh mechanism
	// This is a placeholder for the actual implementation
	return nil
}

// User represents your application's user model
type User struct {
	ID           uuid.UUID
	Email        string
	Name         string
	DisplayName  string
	GoogleID     string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApiKey       string
	ApiKeyDev    string
	Refreshtoken string
	Accesstoken  string
	Expiry       time.Time
	Tokentype    string
	Persona      string
}

// InsertTokenByUserIDParams represents the parameters for inserting a token
type InsertTokenByUserIDParams struct {
	ID           uuid.UUID
	Accesstoken  string
	Refreshtoken string
	Expiry       time.Time
	Tokentype    string
}

// TokenResponse represents the OAuth token response from Microsoft
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
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

// OAuthConfig holds the configuration for Microsoft OAuth
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	TenantID     string
	RedirectURL  string
	StateKey     string
	Store        *sessions.CookieStore
}

func NewOAuthConfig() *OAuthConfig {
	key := make([]byte, 32)
	rand.Read(key)

	return &OAuthConfig{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		TenantID:     os.Getenv("TENANT_ID"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		StateKey:     "microsoft-oauth-state",
		Store:        sessions.NewCookieStore(key),
	}
}

func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (mc *MicrosoftClient) LoginHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	state, err := mc.MicrosoftGenerateStateOauthCookie(w)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	authURL := fmt.Sprintf(
		"https://login.microsoftonline.com/%s/oauth2/v2.0/authorize?"+
			"client_id=%s"+
			"&response_type=code"+
			"&redirect_uri=%s"+
			"&scope=offline_access%%20https://graph.microsoft.com/.default"+
			"&state=%s",
		mc.config.TenantID,
		mc.config.ClientID,
		url.QueryEscape(mc.config.RedirectURL),
		state,
	)

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (mc *MicrosoftClient) CallbackHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		http.Error(w, "Failed to get state cookie", http.StatusBadRequest)
		return
	}
	if r.FormValue("state") != oauthState.Value {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := mc.exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	userInfo, err := mc.getUserInfo(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	log.Println("userInfo", userInfo)
	// Handle user (store in database, etc.)
	if err := mc.handleUser(r.Context(), userInfo, token); err != nil {
		http.Error(w, "Failed to handle user", http.StatusInternalServerError)
	}

	// Set cookie and redirect
	cookie := &http.Cookie{
		Name:     "loggedIn",
		Value:    userInfo.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
		Domain:   os.Getenv("DOMAIN"),
	}
	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// Helper functions (implement these)
func (mc *MicrosoftClient) MicrosoftGenerateStateOauthCookie(w http.ResponseWriter) (string, error) {
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

func (mc *MicrosoftClient) exchangeCodeForToken(code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("client_id", mc.config.ClientID)
	data.Set("client_secret", mc.config.ClientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", mc.config.RedirectURL)

	resp, err := http.PostForm(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", mc.config.TenantID), data)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}
	defer resp.Body.Close()

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &token, nil
}

func (mc *MicrosoftClient) handleUser(ctx context.Context, userInfo *UserInfo, token *TokenResponse) error {
	user, err := mc.db.GetUserByMicrosoftID(ctx, sql.NullString{String: userInfo.ID, Valid: true})

	if err != nil {
		// User doesn't exist, create a new one
		user, err = mc.db.CreateUserWithMicrosoftID(ctx, store.CreateUserWithMicrosoftIDParams{
			MicrosoftID: sql.NullString{String: userInfo.ID, Valid: true},
			Name:        userInfo.DisplayName,
			Email:       userInfo.Email,
			DisplayName: userInfo.DisplayName,
		})
		if err != nil {
			log.Println("failed to create user: %w", err)
		}
	}

	encryptedAccessToken, err := Encrypt(token.AccessToken, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		fmt.Errorf("error encrypting access token: %w", err)
	}

	encryptedRefreshToken, err := Encrypt(token.RefreshToken, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		fmt.Errorf("error encrypting refresh token: %w", err)
	}

	encryptedTokenType, err := Encrypt(token.TokenType, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		fmt.Errorf("error encrypting token type: %w", err)
	}

	expiryTime := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	_, err = mc.db.InsertTokenByUserID(ctx, store.InsertTokenByUserIDParams{
		ID:           user.ID,
		Accesstoken:  sql.NullString{String: encryptedAccessToken, Valid: true},
		Refreshtoken: sql.NullString{String: encryptedRefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: expiryTime, Valid: true},
		Tokentype:    sql.NullString{String: encryptedTokenType, Valid: true},
	})
	if err != nil {
		fmt.Errorf("failed to insert token: %w", err)
	}

	return nil
}

func (mc *MicrosoftClient) getUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (mc *MicrosoftClient) storeToken(ctx context.Context, params store.InsertTokenByUserIDParams) (store.User, error) {
	return mc.db.InsertTokenByUserID(ctx, params)
}

func (mc *MicrosoftClient) MicrosoftRefreshToken(ctx context.Context, userID uuid.UUID) error {
	// Get existing user with token information
	existingToken, err := mc.db.GetAccessTokenByUserId(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get access token: %w", err)
	}

	if !existingToken.Valid {
		return fmt.Errorf("no valid access token found for user")
	}

	tokenData := url.Values{}
	tokenData.Set("client_id", mc.config.ClientID)
	tokenData.Set("client_secret", mc.config.ClientSecret)
	tokenData.Set("refresh_token", existingToken.String)
	tokenData.Set("grant_type", "refresh_token")

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", mc.config.TenantID)
	resp, err := http.PostForm(tokenURL, tokenData)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	var newToken TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&newToken); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	// Calculate new expiration time
	expiryTime := time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
	encryptedAccessToken, err := Encrypt(newToken.AccessToken, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}
	encryptedRefreshToken, err := Encrypt(newToken.RefreshToken, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	// Store new token information
	_, err = mc.storeToken(ctx, store.InsertTokenByUserIDParams{
		ID:           userID,
		Accesstoken:  sql.NullString{String: encryptedAccessToken, Valid: true},
		Refreshtoken: sql.NullString{String: encryptedRefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: expiryTime, Valid: true},
		Tokentype:    sql.NullString{String: newToken.TokenType, Valid: true},
	})

	return err
}

// GetValidToken retrieves a valid token for the user, refreshing if necessary
func (mc *MicrosoftClient) GetValidToken(ctx context.Context, userID uuid.UUID) (string, error) {
	token, err := mc.db.GetTokenByUser(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	// refresh token if expired
	if token.Expiry.Valid && token.Expiry.Time.Before(time.Now()) {
		err = mc.MicrosoftRefreshToken(ctx, userID)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}
		token, err = mc.db.GetTokenByUser(ctx, userID)
		if err != nil {
			return "", fmt.Errorf("failed to refresh token: %w", err)
		}
	}
	// Here you might want to check token expiration and refresh if needed
	// You can add this logic based on your needs

	decryptedToken, err := Decrypt(token.Accesstoken.String, os.Getenv("ENCRYPTION_KEY"))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}

	return decryptedToken, nil
}
