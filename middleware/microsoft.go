package middleware

import (
	"context"
	"emaildrafter/database/store"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
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

func LoginHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	// Implementation for Microsoft login
}

func CallbackHandlerMicrosoft(w http.ResponseWriter, r *http.Request) {
	// Implementation for Microsoft callback
}
