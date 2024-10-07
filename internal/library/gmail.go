package library

// this library will contain all of the handlers for pulling down emails, reading and drafting a response.

import (
	"context"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"emaildrafter/middleware"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/generative-ai-go/genai"
	"golang.org/x/exp/rand"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

// Google OAuth2 Configuration
var (
	config *oauth2.Config
	logger *slog.Logger
)

// TimeSlot represents a block of time with a start and end.
type TimeSlot struct {
	StartTime time.Time // The start time of the time slot
	EndTime   time.Time // The end time of the time slot
}

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

// PartialMetadata stores email metadata. Some fields may sound redundant, but
// in fact have different contexts. Some are slices of string because the ones
// that have multiple values are still being sorted from those that don't.
type PartialMetadata struct {
	// Sender is the entity that originally created and sent the message
	Sender string
	// From is the entity that sent the message to you (e.g. googlegroups). Most
	// of the time this information is only relevant to mailing lists.
	From string
	// Subject is the email subject
	Subject string
	// Mailing list contains the name of the mailing list that the email was
	// posted to, if any.
	MailingList string
	// CC is the "carbon copy" list of addresses
	CC []string
	// To is the recipient of the email.
	To []string
	// ThreadTopic contains the topic of the thread (e.g. google groups threads)
	ThreadTopic []string
	// DeliveredTo is who the email was sent to. This can contain multiple
	// addresses if the email was forwarded.
	DeliveredTo []string
}

type mail_from_email struct {
	body          string
	email_address string
	mail_id       string
}

func ErrorHanlder(err error, line_number string) {
	if err != nil {
		log.Printf("Error: %v", err)
	} else {
		fmt.Println("Success")
		fmt.Printf(line_number)
	}
}

func GmailCompose(token *oauth2.Token, user store.User, q *store.Queries) error {
	ctx := context.Background()
	client := config.Client(ctx, token)
	gmailService, err := gmail.New(client)
	if err != nil {
		return fmt.Errorf("failed to create Gmail service: %w", err)
	}

	messages, err := GetMessages(gmailService, 15)
	if err != nil {
		return fmt.Errorf("failed to get messages: %w", err)
	}

	for _, msg := range messages {
		if shouldProcessMessage(msg) {
			// Check if the message has already been processed
			processed, err := q.IsMessageProcessed(ctx, msg.Id)
			if err != nil {
				log.Printf("Error checking if message %s is processed: %v", msg.Id, err)
				continue
			}
			if processed {
				log.Printf("Skipping message %s: Already processed", msg.Id)
				continue
			}

			// Check if a draft already exists for this message
			hasDraft, err := checkForExistingDraft(gmailService, msg.ThreadId)
			logger.Info("Has Draft:", hasDraft)

			if err != nil {
				log.Printf("Error checking for existing draft for message %s: %v", msg.Id, err)
				continue
			}

			if !hasDraft {
				logger.Info("Inside has draft")
				if err := processMessage(gmailService, msg, user, q); err != nil {
					log.Printf("Error processing message %s: %v", msg.Id, err)
					continue
				}

				// Mark the message as processed
				if err := q.MarkMessageAsProcessed(ctx, msg.Id); err != nil {
					log.Printf("Error marking message %s as processed: %v", msg.Id, err)
				}
			} else {
				log.Printf("Skipping message %s: Draft already exists", msg.Id)
			}
		}
	}

	return nil
}

func checkForExistingDraft(gmailService *gmail.Service, threadId string) (bool, error) {
	drafts, err := gmailService.Users.Drafts.List("me").Q(fmt.Sprintf("threadId:%s", threadId)).Do()
	if err != nil {
		return false, fmt.Errorf("failed to list drafts: %w", err)
	}

	return len(drafts.Drafts) > 0, nil
}
func shouldProcessMessage(msg *gmail.Message) bool {
	for _, label := range msg.LabelIds {
		if label == "DRAFT" || label == "CATEGORY_PROMOTIONS" {
			return false
		}
		if label == "INBOX" {
			return true
		}
	}
	return false
}

func processMessage(gmailService *gmail.Service, msg *gmail.Message, user store.User, q *store.Queries) error {
	bodyMessage, err := GetBody(msg, "text/plain")
	if err != nil {
		return fmt.Errorf("failed to get message body: %w", err)
	}

	if strings.Contains(strings.ToLower(bodyMessage), "unsubscribe") || bodyMessage == "" {
		return nil
	}

	metaData := GetPartialMetadata(msg)
	response, _ := DraftResponse(bodyMessage, user, q)
	draft := createDraft(metaData, response, msg.ThreadId)

	_, err = gmailService.Users.Drafts.Create("me", draft).Do()
	if err != nil {
		return fmt.Errorf("failed to create draft: %w", err)
	}

	log.Println("Draft created successfully")
	return nil
}

func createDraft(metaData *PartialMetadata, response, threadId string) *gmail.Draft {
	messageStr := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		metaData.From,
		metaData.From,
		metaData.Subject,
		response,
	)

	message := &gmail.Message{
		Raw:      base64.URLEncoding.EncodeToString([]byte(messageStr)),
		ThreadId: threadId,
	}

	return &gmail.Draft{Message: message}
}

// promptStringCreator generates a prompt for responding to an email based on the user's persona.
// It returns a boolean indicating whether a booking was requested.
func promptStringCreator(user store.User, email string) (bool, string) {
	var personaDescription string
	if user.Persona.Valid {
		personaDescription = fmt.Sprintf("As a representative of the '%s' persona, ", user.Persona.String)
	} else {
		personaDescription = "In your usual style, "
	}

	// Check for booking request keywords
	bookingRequested := strings.Contains(strings.ToLower(email), "book") || strings.Contains(strings.ToLower(email), "schedule")

	// Create the prompt
	prompt := fmt.Sprintf(
		"%s you are tasked with crafting a response to the following email:\n\n\"%s\"\n\nPlease ensure that your reply is concise and accurate, while maintaining the same tone as the original message. Conclude your response with your name: %s.",
		personaDescription, email, user.Name,
	)

	return bookingRequested, prompt
}

// promptStringCreatorWithTimeslots generates a prompt for responding to an email based on the user's persona,
// considering booked time slots and available time slots.
func promptStringCreatorWithTimeslots(user store.User, email string, availableSlots []string) string {
	var personaDescription string
	if user.Persona.Valid {
		personaDescription = fmt.Sprintf("This is who you are,'%s' at all times you must consider this and their likely needs., ", user.Persona.String)
	} else {
		personaDescription = "In your usual style, "
	}

	// Determine typical business hours based on available slots

	// Prompt construction
	prompt := fmt.Sprintf(
		"%sYou are tasked with crafting a response to the following email:\n\n\"%s\"\n\n\n\nWhen selecting an available time slot, ensure it aligns with the individual’s preferences based on their personal description. Choose one of the following available slots: %v.\n\nPlease ensure that your reply is concise and accurate while maintaining the same tone as the original message. Conclude your response with your name: %s.",
		personaDescription, email, availableSlots, user.Name,
	)

	return prompt
}

// drafts a response using Gemini.
// BackoffRetry attempts to retry a function with exponential backoff and jitter
func BackoffRetry(attempts int, initialDelay time.Duration, fn func() (string, error)) (string, error) {
	delay := initialDelay
	for i := 0; i < attempts; i++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		log.Printf("Attempt %d failed: %v. Retrying in %v...\n", i+1, err, delay)

		// Add jitter to avoid thundering herd problem
		jitter := time.Duration(rand.Int63n(int64(delay / 2)))
		time.Sleep(delay + jitter)

		// Exponential backoff
		delay *= 2
	}
	return "", errors.New("all retry attempts failed")
}

// DraftResponse drafts a response using Gemini with backoff
func DraftResponse(bodyMessage string, user store.User, queries *store.Queries) (string, error) {
	ctx := context.Background()

	// Access the API key as an environment variable
	client, err := genai.NewClient(ctx, option.WithAPIKey(os.Getenv("GEMINI_API_KEY")))
	if err != nil {
		return "", fmt.Errorf("failed to create client: %v", err)
	}
	defer client.Close()

	log.Println("Line 192 in Draft Response")

	// Create the prompt and check if booking is requested
	bookingRequested, prompt := promptStringCreator(user, bodyMessage)
	log.Println("Prompt is: " + prompt)

	model := client.GenerativeModel("gemini-1.5-pro")

	// Function to generate content using the specified model
	generateContent := func(model *genai.GenerativeModel) (string, error) {
		resp, err := model.GenerateContent(ctx, genai.Text(prompt))
		if err != nil {
			return "", err
		}
		bs, _ := json.Marshal(resp.Candidates[len(resp.Candidates)-1].Content.Parts[len(resp.Candidates[len(resp.Candidates)-1].Content.Parts)-1])
		responseString := string(bs)
		responseString = strings.Replace(responseString[1:len(responseString)-1], `\n`, "\n", -1)
		return responseString, nil
	}

	// Retry the content generation with backoff and error handling
	responseString, err := BackoffRetry(5, 2*time.Second, func() (string, error) {
		model := client.GenerativeModel("gemini-1.5-pro")

		response, err := generateContent(model)
		if err != nil {
			// Check if the error contains "429" in its string representation
			if strings.Contains(err.Error(), "429") {
				// If error code is 429, switch to a different model for retry
				model = client.GenerativeModel("gemini-1.0-pro")
				response, err = generateContent(model)
			}
		}
		return response, err
	})

	if err != nil {
		return "", fmt.Errorf("failed to generate response after multiple retries: %v", err)
	}

	// Retry the "concise" response generation with backoff
	conciseContent := func() (string, error) {
		resp, err := model.GenerateContent(ctx, genai.Text("Make this more concise: "+responseString+"."))
		if err != nil {
			return "", err
		}
		bs, _ := json.Marshal(resp.Candidates[len(resp.Candidates)-1].Content.Parts[len(resp.Candidates[len(resp.Candidates)-1].Content.Parts)-1])
		responseString = string(bs)
		responseString = strings.Replace(responseString[1:len(responseString)-1], `\n`, "\n", -1)
		return responseString, nil
	}

	// Final concise response
	finalResponse, err := BackoffRetry(5, 2*time.Second, conciseContent)
	if err != nil {
		return "", fmt.Errorf("failed to make the response concise after multiple retries: %v", err)
	}

	// If a booking was requested, handle the booking logic
	if bookingRequested {
		log.Println("Booking reference found, initiating calendar booking...")

		// Call CalendarHandler to handle booking
		availableSlots, err := CalendarHandler(user, queries)
		if err != nil {
			return finalResponse, fmt.Errorf("failed to handle calendar booking: %v", err)
		}

		// Generate a new prompt that includes time slots
		promptWithTimeslots := promptStringCreatorWithTimeslots(user, bodyMessage, availableSlots)

		// Generate response using the new prompt with timeslots
		timeslotResponse, err := BackoffRetry(5, 2*time.Second, func() (string, error) {
			resp, err := model.GenerateContent(ctx, genai.Text(promptWithTimeslots))
			if err != nil {
				return "", err
			}
			bs, _ := json.Marshal(resp.Candidates[len(resp.Candidates)-1].Content.Parts[len(resp.Candidates[len(resp.Candidates)-1].Content.Parts)-1])
			responseString = string(bs)
			responseString = strings.Replace(responseString[1:len(responseString)-1], `\n`, "\n", -1)
			return responseString, nil
		})

		if err != nil {
			return "", fmt.Errorf("failed to generate timeslot response after multiple retries: %v", err)
		}

		// Use the timeslot response as the final response
		finalResponse = timeslotResponse
	}

	return finalResponse, nil
}

// Takes in a single message, then returns a draft message
func EmailDrafter(msg *gmail.Message, body_message []byte) (email_draft gmail.Draft) {
	var message gmail.Message
	var message_draft gmail.Draft
	message.Raw = base64.URLEncoding.EncodeToString(body_message)
	message_draft.Message = &message

	return message_draft
}

// I need to abstract out the draft function for mail.draft. Then write a function that takes in a body of an email amd generates a response.

// MarkAs allows you to mark an email with a specific label using the
// gmail.ModifyMessageRequest struct.
func MarkAs(srv *gmail.Service, msg *gmail.Message, req *gmail.ModifyMessageRequest) (*gmail.Message, error) {
	return srv.Users.Messages.Modify("me", msg.Id, req).Do()
}

// MarkAllAsRead removes the UNREAD label from all emails.
func MarkAllAsRead(srv *gmail.Service) error {
	// Request to remove the label ID "UNREAD"
	req := &gmail.ModifyMessageRequest{
		RemoveLabelIds: []string{"UNREAD"},
	}

	// Get the messages labeled "UNREAD"
	msgs, err := Query(srv, "label:UNREAD")
	if err != nil {
		return err
	}

	// For each UNREAD message, request to remove the "UNREAD" label (thus
	// maring it as "READ").
	for _, v := range msgs {
		_, err := MarkAs(srv, v, req)
		if err != nil {
			return err
		}
	}

	return nil
}

// / GetBody gets, decodes, and returns the body of the email.
// It first tries to find the body with the requested mimeType.
// If not found, it falls back to other common types, and finally to any available content.
func GetBody(msg *gmail.Message, preferredMimeType string) (string, error) {
	if msg == nil || msg.Payload == nil {
		return "", errors.New("invalid message or payload")
	}

	// Define a priority list of MIME types to check
	mimeTypes := []string{preferredMimeType, "text/plain", "text/html"}

	// Try to get the body using each MIME type in order
	for _, mimeType := range mimeTypes {
		body, err := getBodyFromParts(msg.Payload.Parts, mimeType)
		if err == nil {
			return body, nil
		}

		// Check the payload body if parts don't contain the desired MIME type
		if msg.Payload.MimeType == mimeType && msg.Payload.Body != nil && msg.Payload.Body.Size > 0 {
			return decodeEmailBody(msg.Payload.Body.Data)
		}
	}

	// If still not found, return any available content
	return getAnyAvailableBody(msg.Payload)
}

func getBodyFromParts(parts []*gmail.MessagePart, mimeType string) (string, error) {
	for _, part := range parts {
		if part.MimeType == "multipart/alternative" || part.MimeType == "multipart/mixed" {
			body, err := getBodyFromParts(part.Parts, mimeType)
			if err == nil {
				return body, nil
			}
		} else if part.MimeType == mimeType && part.Body != nil && part.Body.Size > 0 {
			return decodeEmailBody(part.Body.Data)
		}
	}
	return "", errors.New("body not found in parts")
}

func getAnyAvailableBody(payload *gmail.MessagePart) (string, error) {
	if payload.Body != nil && payload.Body.Size > 0 {
		return decodeEmailBody(payload.Body.Data)
	}

	for _, part := range payload.Parts {
		if part.Body != nil && part.Body.Size > 0 {
			return decodeEmailBody(part.Body.Data)
		}
		if len(part.Parts) > 0 {
			body, err := getAnyAvailableBody(part)
			if err == nil {
				return body, nil
			}
		}
	}

	return "", errors.New("no available body content found")
}

func decodeEmailBody(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("failed to decode email body: %w", err)
	}
	return string(decoded), nil
}

// GetPartialMetadata gets some of the useful metadata from the headers.
func GetPartialMetadata(msg *gmail.Message) *PartialMetadata {
	info := &PartialMetadata{}
	for _, v := range msg.Payload.Headers {
		switch strings.ToLower(v.Name) {
		case "sender":
			info.Sender = v.Value
		case "from":
			info.From = v.Value
		case "subject":
			info.Subject = v.Value
		case "mailing-list":
			info.MailingList = v.Value
		case "cc":
			info.CC = append(info.CC, v.Value)
		case "to":
			info.To = append(info.To, v.Value)
		case "thread-Topic":
			info.ThreadTopic = append(info.ThreadTopic, v.Value)
		case "delivered-To":
			info.DeliveredTo = append(info.DeliveredTo, v.Value)
		}
	}
	return info
}

// decodeEmailBody is used to decode the email body by converting from

// ReceivedTime parses and converts a Unix time stamp into a human readable
// format ().
func ReceivedTime(datetime int64) (time.Time, error) {
	conv := strconv.FormatInt(datetime, 10)
	// Remove trailing zeros.
	conv = conv[:len(conv)-3]
	tc, err := strconv.ParseInt(conv, 10, 64)
	if err != nil {
		return time.Unix(0, 0), err
	}
	return time.Unix(tc, 0), nil
}

// Query queries the inbox for a string following the search style of the gmail
// online mailbox.
// example:
// "in:sent after:2017/01/01 before:2017/01/30"
func Query(srv *gmail.Service, query string) ([]*gmail.Message, error) {
	inbox, err := srv.Users.Messages.List("me").Q(query).Do()
	if err != nil {
		return []*gmail.Message{}, err
	}
	msgs, err := getByID(srv, inbox)
	if err != nil {
		return msgs, err
	}
	return msgs, nil
}

// getByID gets emails individually by ID. This is necessary because this is
// how the gmail API is set [0][1] up apparently (but why?).
// [0] https://developers.google.com/gmail/api/v1/reference/users/messages/get
// [1] https://stackoverflow.com/questions/36365172/message-payload-is-always-null-for-all-messages-how-do-i-get-this-data
func getByID(srv *gmail.Service, msgs *gmail.ListMessagesResponse) ([]*gmail.Message, error) {
	var msgSlice []*gmail.Message
	for _, v := range msgs.Messages {
		msg, err := srv.Users.Messages.Get("me", v.Id).Do()
		if err != nil {
			return msgSlice, err
		}
		msgSlice = append(msgSlice, msg)
	}
	return msgSlice, nil
}

// GetMessages gets and returns gmail messages
func GetMessages(srv *gmail.Service, howMany uint) ([]*gmail.Message, error) {
	var msgSlice []*gmail.Message

	// Get the messages
	inbox, err := srv.Users.Messages.List("me").MaxResults(int64(howMany)).Do()

	if err != nil {
		return msgSlice, err
	}

	msgs, err := getByID(srv, inbox)
	if err != nil {
		return msgs, err
	}

	return msgs, nil
}

// CheckForUnreadByLabel checks for unread mail matching the specified label.
// NOTE: When checking your inbox for unread messages, it's not uncommon for
// it to return thousands of unread messages that you don't know about. To see
// them in gmail, query your mail for "label:unread". For CheckForUnreadByLabel
// to work properly you need to mark all mail as read either through gmail or
// through the MarkAllAsRead() function found in this library.
func CheckForUnreadByLabel(srv *gmail.Service, label string) (int64, error) {
	inbox, err := srv.Users.Labels.Get("me", label).Do()
	if err != nil {
		return -1, err
	}

	if inbox.MessagesUnread == 0 && inbox.ThreadsUnread == 0 {
		return 0, nil
	}

	return inbox.MessagesUnread + inbox.ThreadsUnread, nil
}

// CheckForUnread checks for mail labeled "UNREAD".
// NOTE: When checking your inbox for unread messages, it's not uncommon for
// it to return thousands of unread messages that you don't know about. To see
// them in gmail, query your mail for "label:unread". For CheckForUnread to
// work properly you need to mark all mail as read either through gmail or
// through the MarkAllAsRead() function found in this library.
func CheckForUnread(srv *gmail.Service) (int64, error) {
	inbox, err := srv.Users.Labels.Get("me", "UNREAD").Do()
	if err != nil {
		return -1, err
	}

	if inbox.MessagesUnread == 0 && inbox.ThreadsUnread == 0 {
		return 0, nil
	}

	return inbox.MessagesUnread + inbox.ThreadsUnread, nil
}

// GetLabels gets a list of the labels used in the users inbox.
func GetLabels(srv *gmail.Service) (*gmail.ListLabelsResponse, error) {
	return srv.Users.Labels.List("me").Do()
}

// createMeetingTimeRecommendationPrompt creates a structured prompt for Gemini to recommend meeting times
func CreateMeetingTimeRecommendationPrompt(bodyMessage string, bookedSlots []TimeSlot, availableSlots []TimeSlot) string {
	prompt := "You are tasked with recommending the best time slots for scheduling a meeting. Below are the user's booked and available time slots. Please recommend up to 3 meeting times based on the availability and ensure that the times are at least 1 hour long.\n\n"

	// Include booked time slots
	prompt += "Booked Times:\n"
	for _, slot := range bookedSlots {
		prompt += fmt.Sprintf("Start: %s, End: %s\n", slot.StartTime.Format(time.RFC3339), slot.EndTime.Format(time.RFC3339))
	}

	// Include available time slots
	prompt += "\nAvailable Times:\n"
	for _, slot := range availableSlots {
		prompt += fmt.Sprintf("Start: %s, End: %s\n", slot.StartTime.Format(time.RFC3339), slot.EndTime.Format(time.RFC3339))
	}

	// Body message for context
	prompt += "\nBody Message: " + bodyMessage + "\n"

	// Instruction to recommend meeting times
	prompt += "Please recommend up to 3 meeting times that fit within the available time slots."

	return prompt
}

// This is going to be the calendar handler. Where the agent will be able to look at your calendar and make recommendations for when to book a meeting in, and then use this within the drafted response when appropriate.
func CalendarHandler(user store.User, queries *store.Queries) ([]string, error) {
	// Initialize OAuth and retrieve the user's token from the session or database
	if err := InitializeOAuth(); err != nil {
		return nil, fmt.Errorf("failed to initialize OAuth: %v", err)
	}

	// Fetch the user's refresh token from the database
	refreshToken, err := queries.GetRefreshTokenByUserId(context.Background(), user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve refresh token: %v", err)
	}

	// Decrypt the refresh token
	decryptedRefreshToken, err := middleware.Decrypt(refreshToken.String, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %v", err)
	}

	// Fetch the user's refresh token from the database
	accessToken, err := queries.GetAccessTokenByUserId(context.Background(), user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve refresh token: %v", err)
	}

	// Decrypt the refresh token
	decryptedAccessToken, err := middleware.Decrypt(accessToken.String, os.Getenv("KEY"))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %v", err)
	}

	// Create token source with the decrypted refresh token
	tokenSource := config.TokenSource(context.Background(), &oauth2.Token{
		RefreshToken: decryptedRefreshToken,
		AccessToken:  decryptedAccessToken,
	})

	// Refresh the token
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %v", err)
	}

	// Fetch user's calendar events and find available slots
	availableSlots, err := getAvailableCalendarSlots(context.Background(), token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve calendar slots: %v", err)
	}

	return availableSlots, nil
}

func getAvailableCalendarSlots(ctx context.Context, token *oauth2.Token) ([]string, error) {
	client := config.Client(ctx, token)

	// Define the Google Calendar API endpoint for retrieving events
	calendarServiceURL := "https://www.googleapis.com/calendar/v3/calendars/primary/events"

	// Get current time and look for availability for the next 7 days
	now := time.Now().Format(time.RFC3339)
	oneWeekLater := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)

	url := fmt.Sprintf("%s?timeMin=%s&timeMax=%s&singleEvents=true&orderBy=startTime", calendarServiceURL, now, oneWeekLater)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get calendar events: %w", err)
	}
	defer resp.Body.Close()

	// Parse the response from Google Calendar API
	var eventsResponse struct {
		Items []struct {
			Start struct {
				DateTime string `json:"dateTime"`
			} `json:"start"`
			End struct {
				DateTime string `json:"dateTime"`
			} `json:"end"`
		} `json:"items"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&eventsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode calendar events: %w", err)
	}

	// Find gaps between events
	return findAvailableTimeSlots(eventsResponse.Items), nil
}

func findAvailableTimeSlots(events []struct {
	Start struct {
		DateTime string `json:"dateTime"`
	} `json:"start"`
	End struct {
		DateTime string `json:"dateTime"`
	} `json:"end"`
}) []string {
	var availableSlots []string
	now := time.Now()

	// Iterate through the events and find gaps
	for _, event := range events {
		eventStart, _ := time.Parse(time.RFC3339, event.Start.DateTime)
		eventEnd, _ := time.Parse(time.RFC3339, event.End.DateTime)

		if eventEnd.After(now) {
			gapDuration := eventStart.Sub(now)
			if gapDuration.Hours() >= 1 {
				availableSlots = append(availableSlots, fmt.Sprintf("Available from %s to %s", now.Format(time.RFC1123), eventStart.Format(time.RFC1123)))
			}
			now = eventEnd
		}
	}

	// Check for availability after the last event
	oneWeekLater := time.Now().Add(7 * 24 * time.Hour)
	if oneWeekLater.After(now) {
		availableSlots = append(availableSlots, fmt.Sprintf("Available from %s to %s", now.Format(time.RFC1123), oneWeekLater.Format(time.RFC1123)))
	}

	return availableSlots
}
