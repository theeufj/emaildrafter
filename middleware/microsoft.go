package middleware

import (
	"context"
	"database/sql"
	"emaildrafter/database/store"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/joho/godotenv"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"golang.org/x/exp/rand"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type accessToken azcore.AccessToken

// Updated microsoftMail struct to match the email message structure
type microsoftMail struct {
	Messages []EmailMessage `json:"messages"`
	Error    string         `json:"error,omitempty"`
}

type EmailMessage struct {
	Subject          string    `json:"subject"`
	From             string    `json:"from"`
	ReceivedDateTime time.Time `json:"receivedDateTime"`
	Body             string    `json:"body"`
	IsRead           bool      `json:"isRead"`
	ID               string    `json:"id"`
}

type microsoftUser struct {
	DisplayName       string `json:"displayName"`
	GivenName         string `json:"givenName"`
	Surname           string `json:"surname"`
	UserPrincipalName string `json:"userPrincipalName"`
	Id                string `json:"id"`
	Mail              string `json:"mail"`
	MobilePhone       string `json:"mobilePhone"`
	JobTitle          string `json:"jobTitle"`
	OfficeLocation    string `json:"officeLocation"`
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var ssoMicrofsoft *oauth2.Config
var RandomString = RandStringBytes(512)

// GraphHelper is a helper for the Microsoft Graph API
// the following needs to interative micrsoft graph api
func init() {
	err := godotenv.Load("./.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	ssoMicrofsoft = &oauth2.Config{
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"user.read", "offline_access", "Mail.ReadWrite", "mail.send"},
		Endpoint:     microsoft.AzureADEndpoint(os.Getenv("TENANT_ID")),
	}
}
func create_token(email string, queries *store.Queries) accessToken {
	microfsoftUserReturned, _ := queries.GetUserByEmail(context.Background(), email)
	tokenRefresh := &oauth2.Token{
		AccessToken:  microfsoftUserReturned.Accesstoken.String,
		TokenType:    microfsoftUserReturned.Tokentype.String,
		RefreshToken: microfsoftUserReturned.Refreshtoken.String,
		Expiry:       microfsoftUserReturned.Expiry.Time,
	}
	t := ssoMicrofsoft.TokenSource(context.Background(), tokenRefresh)
	// updates the token stored in the db everytime we call create token.
	queries.InsertTokenByUserID(context.Background(), store.InsertTokenByUserIDParams{
		ID:           microfsoftUserReturned.ID,
		Accesstoken:  sql.NullString{String: tokenRefresh.AccessToken, Valid: true},
		Tokentype:    sql.NullString{String: tokenRefresh.TokenType, Valid: true},
		Refreshtoken: sql.NullString{String: tokenRefresh.RefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: tokenRefresh.Expiry, Valid: true},
	})
	newToken, _ := t.Token()
	myTk := accessToken(azcore.AccessToken{
		Token:     newToken.AccessToken, // replace with real token
		ExpiresOn: newToken.Expiry,      // replace with real expiration date
	})
	var _ azcore.TokenCredential = myTk
	return myTk
}

// Updated SendMail function with better error handling

func SendMail(contentBond *string, id string, email string, queries *store.Queries) error {
	t := create_token(email, queries)
	graphClient, err := msgraphsdk.NewGraphServiceClientWithCredentials(t, []string{
		"user.read",
		"Mail.ReadWrite",
		"offline_access",
	})
	if err != nil {
		return fmt.Errorf("failed to create graph client: %w", err)
	}

	requestBody := graphmodels.NewMessage()
	body := graphmodels.NewItemBody()
	contentType := graphmodels.TEXT_BODYTYPE
	body.SetContentType(&contentType)
	body.SetContent(contentBond)
	requestBody.SetBody(body)

	sendMailBody := users.NewItemMessagesItemCreateReplyPostRequestBody()
	sendMailBody.SetMessage(requestBody)

	_, err = graphClient.Me().Messages().ByMessageId(id).CreateReply().Post(
		context.Background(),
		sendMailBody,
		nil, // Using nil for config since we don't need custom headers
	)

	if err != nil {
		// Check for OData error
		if odataErr, ok := err.(*odataerrors.ODataError); ok {
			log.Println(odataErr.Error())
		}

		// Check for HTTP response error
		if errResp, ok := err.(interface{ Response() *http.Response }); ok && errResp.Response() != nil {
			resp := errResp.Response()
			body, _ := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			return fmt.Errorf("failed to send mail: status=%d, body=%s",
				resp.StatusCode, string(body))
		}
		return fmt.Errorf("failed to send mail: %w", err)
	}

	return nil
}

// Ensure accessToken implements TokenCredential interface
func (a accessToken) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken(a), nil
}

// handles the mailbox and drafts a response to the 3 most recent emails.
// func GetMailBoxMicrosoft(email string, user store.User, queries *store.Queries) microsoftMail {
// 	log.Println("getting mailbox for user", user.ID)
// 	newMail := microsoftMail{
// 		Messages: make([]EmailMessage, 0),
// 	}

// 	t := create_token(email, queries)
// 	log.Printf("Debug - Token: %s (first 20 chars)", t.Token[:20])
// 	log.Printf("Debug - Token expiry: %v", t.ExpiresOn)

// 	// Create a debugging transport
// 	debugTransport := &debugTransport{
// 		base: http.DefaultTransport,
// 	}

// 	// Create a custom HTTP client with the debug transport
// 	httpClient := &http.Client{
// 		Transport: debugTransport,
// 	}

// 	// Create a TokenCredential from the accessToken
// 	tokenCredential := msgraphsdk.NewTokenCredential(string(t.Token))

// 	// Create adapter with custom client and token credential
// 	adapter, err := msgraphsdk.NewGraphRequestAdapter(tokenCredential)
// 	if err != nil {
// 		log.Printf("Error creating adapter: %v", err)
// 		newMail.Error = "Failed to create graph adapter"
// 		return newMail
// 	}

// 	// Set the custom HTTP client on the adapter
// 	adapter.SetHttpClient(httpClient)

// 	// Create graph client with the custom adapter
// 	graphClient := msgraphsdk.NewGraphServiceClient(adapter)

// 	var topValue int32 = 3
// 	query := users.ItemMailFoldersItemMessagesRequestBuilderGetQueryParameters{
// 		Select: []string{
// 			"from",
// 			"isRead",
// 			"receivedDateTime",
// 			"subject",
// 			"body",
// 			"id",
// 		},
// 		Top:     &topValue,
// 		Orderby: []string{"receivedDateTime DESC"},
// 	}

// 	requestHeaders := users.ItemMailFoldersItemMessagesRequestBuilderGetRequestConfiguration{
// 		QueryParameters: &query,
// 	}

// 	// First, try to get the user profile to verify authentication
// 	userProfile, err := graphClient.Me().Get(context.Background(), nil)
// 	if err != nil {
// 		log.Printf("Error fetching user profile: %v", err)
// 		newMail.Error = fmt.Sprintf("Authentication test failed: %v", err)
// 		return newMail
// 	}
// 	log.Printf("Debug - Successfully authenticated as user: %v", *userProfile.GetDisplayName())

// 	messages, err := graphClient.Me().MailFolders().
// 		ByMailFolderId("inbox").
// 		Messages().
// 		Get(context.Background(), &requestHeaders)

// 	if err != nil {
// 		log.Printf("Error fetching messages: %v", err)

// 		// Check for OData error
// 		if odataErr, ok := err.(*odataerrors.ODataError); ok {
// 			log.Printf("OData error: %v", odataErr)
// 			newMail.Error = fmt.Sprintf("OData error: %v", odataErr)
// 			return newMail
// 		}

// 		// Check for HTTP response error and attempt to read the response body
// 		if errResp, ok := err.(interface{ Response() *http.Response }); ok && errResp.Response() != nil {
// 			resp := errResp.Response()
// 			body, readErr := io.ReadAll(resp.Body)
// 			defer resp.Body.Close()

// 			if readErr != nil {
// 				log.Printf("Error reading response body: %v", readErr)
// 			} else {
// 				log.Printf("Response Status: %d", resp.StatusCode)
// 				log.Printf("Response Headers: %+v", resp.Header)
// 				log.Printf("Response Body: %s", string(body))
// 			}

// 			switch resp.StatusCode {
// 			case 401:
// 				// Try to refresh token
// 				newToken := refreshToken(email, queries)
// 				if newToken != nil {
// 					log.Println("Token refreshed, please retry the operation")
// 					newMail.Error = "Token refreshed, please retry"
// 				} else {
// 					newMail.Error = "Authentication failed and token refresh failed"
// 				}
// 			case 403:
// 				newMail.Error = "Insufficient permissions to access mailbox"
// 			default:
// 				newMail.Error = fmt.Sprintf("Failed to fetch messages (Status %d): %s",
// 					resp.StatusCode, string(body))
// 			}
// 			return newMail
// 		}

// 		// If we can't get more specific error information, return the original error
// 		newMail.Error = fmt.Sprintf("Error fetching messages: %v", err)
// 		return newMail
// 	}

// 	messageValues := messages.GetValue()
// 	log.Printf("Successfully fetched %d messages", len(messageValues))

// 	for _, message := range messageValues {
// 		if message == nil {
// 			continue
// 		}

// 		emailMsg := EmailMessage{}

// 		if subject := message.GetSubject(); subject != nil {
// 			emailMsg.Subject = *subject
// 		}

// 		if from := message.GetFrom(); from != nil {
// 			if emailAddr := from.GetEmailAddress(); emailAddr != nil {
// 				if addr := emailAddr.GetAddress(); addr != nil {
// 					emailMsg.From = *addr
// 				}
// 			}
// 		}

// 		if receivedDateTime := message.GetReceivedDateTime(); receivedDateTime != nil {
// 			emailMsg.ReceivedDateTime = *receivedDateTime
// 		}

// 		if body := message.GetBody(); body != nil {
// 			if content := body.GetContent(); content != nil {
// 				emailMsg.Body = *content
// 			}
// 		}

// 		if isRead := message.GetIsRead(); isRead != nil {
// 			emailMsg.IsRead = *isRead
// 		}

// 		if id := message.GetId(); id != nil {
// 			emailMsg.ID = *id
// 		}

// 		newMail.Messages = append(newMail.Messages, emailMsg)
// 	}

// 	return newMail
// }

// // Debug transport to log request/response details
// type debugTransport struct {
// 	base http.RoundTripper
// }

// func (d *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
// 	log.Printf("Debug - Request URL: %s", req.URL)
// 	log.Printf("Debug - Request Headers: %+v", req.Header)

// 	resp, err := d.base.RoundTrip(req)
// 	if err != nil {
// 		return nil, err
// 	}

// 	log.Printf("Debug - Response Status: %s", resp.Status)
// 	log.Printf("Debug - Response Headers: %+v", resp.Header)

// return resp, nil
// }

// Helper function to refresh token
func refreshToken(email string, queries *store.Queries) *oauth2.Token {
	microfsoftUserReturned, err := queries.GetUserByEmail(context.Background(), email)
	if err != nil {
		log.Printf("Error getting user for token refresh: %v", err)
		return nil
	}

	tokenRefresh := &oauth2.Token{
		AccessToken:  microfsoftUserReturned.Accesstoken.String,
		TokenType:    microfsoftUserReturned.Tokentype.String,
		RefreshToken: microfsoftUserReturned.Refreshtoken.String,
		Expiry:       microfsoftUserReturned.Expiry.Time,
	}

	newToken, err := ssoMicrofsoft.TokenSource(context.Background(), tokenRefresh).Token()
	if err != nil {
		log.Printf("Error refreshing token: %v", err)
		return nil
	}

	_, err = queries.InsertTokenByUserID(context.Background(), store.InsertTokenByUserIDParams{
		ID:           microfsoftUserReturned.ID,
		Accesstoken:  sql.NullString{String: newToken.AccessToken, Valid: true},
		Tokentype:    sql.NullString{String: newToken.TokenType, Valid: true},
		Refreshtoken: sql.NullString{String: newToken.RefreshToken, Valid: true},
		Expiry:       sql.NullTime{Time: newToken.Expiry, Valid: true},
	})
	if err != nil {
		log.Printf("Error updating token in database: %v", err)
		return nil
	}

	return newToken
}

// generate a random string
func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func Signin_microsoft(w http.ResponseWriter, r *http.Request, queries *store.Queries) {
	//log.Println(RandomString)
	url := ssoMicrofsoft.AuthCodeURL(RandomString, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func Callback_microsoft(w http.ResponseWriter, r *http.Request, queries *store.Queries) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	if state != RandomString {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}
	token, err := ssoMicrofsoft.Exchange(oauth2.NoContext, code)
	if err != nil && token == nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//log.Println(state)
	result, err := getInfomation(token)
	log.Println("RESULTS:", result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = queries.GetUserByEmail(context.Background(), result.Mail)
	if err != nil {
		log.Println("user not found, creating user")
		userID, err := queries.CreateUserWithMicrosoftID(context.Background(), store.CreateUserWithMicrosoftIDParams{
			DisplayName: result.DisplayName,
			Name:        result.GivenName,
			Email:       result.Mail,
			MicrosoftID: sql.NullString{String: result.Id, Valid: true},
		})
		if err != nil {
			log.Println("error creating user", err)
		}
		queries.InsertTokenByUserID(context.Background(), store.InsertTokenByUserIDParams{
			ID:           userID.ID,
			Accesstoken:  sql.NullString{String: token.AccessToken, Valid: true},
			Tokentype:    sql.NullString{String: token.TokenType, Valid: true},
			Refreshtoken: sql.NullString{String: token.RefreshToken, Valid: true},
			Expiry:       sql.NullTime{Time: token.Expiry, Valid: true},
		})
	}
	//set cookie up
	vars := JWTValues{}
	vars.Set(result.Id, "Secured")
	vars.Set(result.Mail, "Email")
	toke := CreateJWTTokenForUser(vars)
	cookie := http.Cookie{
		Name:     "secureCookie",
		Value:    toke,
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	cookie_email := http.Cookie{
		Name:     "user_email",
		Value:    result.Mail,
		Path:     "/",
		MaxAge:   360000000,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
	cookie_loggedIn := &http.Cookie{
		Name:     "loggedIn",
		Value:    result.Id,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	}
	http.SetCookie(w, cookie_loggedIn)
	http.SetCookie(w, &cookie)
	http.SetCookie(w, &cookie_email)
	http.Redirect(w, r, "/admin", http.StatusFound)
	log.Println("Logging in...")
	// http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
}

func getInfomation(t *oauth2.Token) (microsoftUser, error) {
	var result microsoftUser
	client := ssoMicrofsoft.Client(oauth2.NoContext, t)
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, err
	}
	//log.Println(string(data))
	err = json.Unmarshal(data, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}
