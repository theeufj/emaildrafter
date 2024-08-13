package library

// this library will contain all of the handlers for pulling down emails, reading and drafting a response.

import (
	"context"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/generative-ai-go/genai"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
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

// drafts all releated information for a given email from a users authorised gamil account.
func GmailCompose(token *oauth2.Token, user store.User) error {
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
			if err := processMessage(gmailService, msg, user); err != nil {
				log.Printf("Error processing message %s: %v", msg.Id, err)
				// Continue processing other messages
			}
		}
	}

	return nil
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

func processMessage(gmailService *gmail.Service, msg *gmail.Message, user store.User) error {
	bodyMessage, err := GetBody(msg, "text/plain")
	if err != nil {
		return fmt.Errorf("failed to get message body: %w", err)
	}

	if strings.Contains(strings.ToLower(bodyMessage), "unsubscribe") || bodyMessage == "" {
		return nil
	}

	metaData := GetPartialMetadata(msg)
	response := DraftResponse(bodyMessage, user)
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

// // this is going to be used to generate the prompt for an email response.
func prompt_string_creator(user store.User, email string) string {
	// if user.PromptCompany.String == "" && user.PromptJobTitle.String == "" {
	// 	prompt = "You are the " + user.PromptJobTitle.String + " of " + user.PromptCompany.String + " You must respond to the this email in a concise, accurate . While also responding with the same tone to the sender. " + email + ". " + " Sign off as " + user.Fullname.String + "."
	// } else {
	// 	prompt = "You must respond to the this email in a concise, accurate . While also responding with the same tone to the sender. " + email + ". " + " Sign off as " + user.Fullname.String + "."
	// }

	prompt := "You must respond to the this email in a concise, accurate . While also responding with the same tone to the sender. " + email + ". " + " Sign off as " + user.Name + "."
	return prompt
}

// drafts a response using Gemini.
func DraftResponse(bodyMessage string, user store.User) (response string) {
	ctx := context.Background()
	// Access your API key as an environment variable (see "Set up your API key" above)
	client, err := genai.NewClient(ctx, option.WithAPIKey(os.Getenv("GEMINI_API_KEY")))

	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	prompt := prompt_string_creator(user, bodyMessage)
	log.Println("prompt is: " + prompt)

	model := client.GenerativeModel("gemini-1.5-pro")
	resp, err := model.GenerateContent(ctx, genai.Text(
		prompt,
	))

	if err != nil {
		log.Fatal(err)
	}
	bs, _ := json.Marshal(resp.Candidates[len(resp.Candidates)-1].Content.Parts[len(resp.Candidates[len(resp.Candidates)-1].Content.Parts)-1])

	responseString := string(bs)
	responseString = responseString[1 : len(responseString)-1]
	responseString = strings.Replace(responseString, `\n`, "\n", -1)

	resp, err = model.GenerateContent(ctx, genai.Text(
		"Make this more concise"+responseString+".",
	))

	if err != nil {
		log.Fatal(err)
	}
	bs, _ = json.Marshal(resp.Candidates[len(resp.Candidates)-1].Content.Parts[len(resp.Candidates[len(resp.Candidates)-1].Content.Parts)-1])

	responseString = string(bs)
	responseString = responseString[1 : len(responseString)-1]
	responseString = strings.Replace(responseString, `\n`, "\n", -1)

	return responseString
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
	log.Println(inbox)
	log.Println(err)

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
