package main

import (
	"context"
	"database/sql"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"emaildrafter/internal/library"
	"emaildrafter/middleware"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
)

var (
	portal = template.Must(template.ParseFiles("templates/portal.tmpl.html"))
)

func catchAllAndRouteToStatic() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/":
			http.ServeFile(w, r, "static/index.html")
		case r.URL.Path == "/robots.txt":
			http.ServeFile(w, r, "static/robots.txt")
		case r.URL.Path == "/favicon.ico":
			http.ServeFile(w, r, "static/favicon.ico")
		default:
			// Attempt to serve from the "static" directory
			filePath := "static" + r.URL.Path
			if _, err := os.Stat(filePath); err == nil {
				http.ServeFile(w, r, filePath)
				return
			}
			// Check for HTML files first
			if _, err := os.Stat("static/" + r.URL.Path + ".html"); err == nil {
				http.ServeFile(w, r, "static/"+r.URL.Path+".html")
				return
			}

			// Check for PDF files
			if _, err := os.Stat("static/" + r.URL.Path + ".pdf"); err == nil {
				http.ServeFile(w, r, "static/"+r.URL.Path+".pdf")
				return
			}

			// If neither HTML nor PDF found, serve a 404
			http.NotFound(w, r)
		}
	}
}

func ServeLoginPage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/login.tmpl.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, nil); err != nil {
		// Handle the template execution error
		http.Error(w, "Internal Server Error", http.StatusInternalServerError) // Or a more specific error
		log.Println("Error executing template:", err)                          // Log the error for debugging
		return                                                                 // Stop further processing
	}
}

func AdminHandler(q store.Queries) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Ensure CSRF middleware is properly initialized
		csrfMiddleware := csrf.Protect([]byte("32-byte-long-auth-key"), csrf.Secure(true))
		handler := csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the user by their google id, which is found in the loggedIn cookie
			cookie, err := r.Cookie("loggedIn")
			// log.Println("cookie", cookie)
			if err != nil {
				// log.Println("Cookie error:", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				// redirect to login page
				http.Redirect(w, r, "/", http.StatusFound)
			}

			user, err := q.GetUserByGoogleID(r.Context(), sql.NullString{String: cookie.Value, Valid: true})
			if err != nil {
				user, err = q.GetUserByMicrosoftID(r.Context(), sql.NullString{String: cookie.Value, Valid: true})
				if err != nil {
					log.Println("error getting user by id", err)
				}
				// log.Println("user by id", user.ID)
			}
			// log.Println("user", user.ID)

			// Generate CSRF token
			csrfToken := csrf.Token(r)
			log.Println("Generated CSRF Token:", csrfToken)
			// Create a map of user and logs
			data := map[string]interface{}{
				"User":      user,
				"csrfToken": csrfToken,
			}

			// // if we are logged in create a microsoft client and get the users emails
			// // Create a MicrosoftClient instance

			// // Call GetAndLogUserEmails
			// log.Println("getting mailbox for user", user.ID)
			// middleware.GetMailBoxMicrosoft(user.Email, user, &q)

			err = portal.Execute(w, data)
			if err != nil {
				log.Printf("Error executing template: %v", err)
				http.Error(w, "Error rendering template", http.StatusInternalServerError)
				return
			}
		}))

		handler.ServeHTTP(w, r)
	}
}

// LogoutHandler handles the logout request
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Create a new cookie with the same name as the login cookie but set its MaxAge to 0
	cookie := &http.Cookie{
		Name:     "loggedIn",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   0, // Set MaxAge to 0 to delete the cookie
		Domain:   env.GetAsString("DOMAIN"),
	}

	// Set the cookie to delete the login cookie
	http.SetCookie(w, cookie)

	// Redirect to the home page or any other desired location
	http.Redirect(w, r, "/", http.StatusFound)
}

func GetUser(r http.Request, q store.Queries) (store.User, error) {
	// Read the JSON request body
	return store.User{}, nil
}

type SetPersonaResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func SetPersonas(q store.Queries) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		err := r.ParseMultipartForm(32 << 20) // 32 MB is the maximum memory used to store parts
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Retrieve the form values
		userIDStr := r.FormValue("user_id")
		persona := r.FormValue("persona")

		// Convert user ID to UUID
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		// Update the persona in the database
		_, err = q.SetPersona(r.Context(), store.SetPersonaParams{
			Persona: sql.NullString{
				String: persona,
				Valid:  true,
			},
			ID: userID,
		})
		if err != nil {
			// Handle database error appropriately (e.g., log, return specific error)
			http.Error(w, "Failed to set persona", http.StatusInternalServerError)
			return
		}

		// Respond with success JSON
		response := SetPersonaResponse{
			Success: true,
			Message: "Persona set successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			// Handle the JSON encoding error
			http.Error(w, "Internal Server Error", http.StatusInternalServerError) // Or a more specific error message
			log.Println("Error encoding JSON response:", err)                      // Log the error for debugging
			return                                                                 // Stop further processing
		}
	}
}

func GeneratePersona(q store.Queries) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the form.
		err := r.ParseMultipartForm(32 << 20) // 32 MB is the maximum memory used to store parts
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Retrieve the form values
		userIDStr := r.FormValue("user_id")

		// Convert user ID to UUID
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}
		user, err := q.GetUserByID(r.Context(), userID)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		ctx := context.Background()
		token, err := middleware.HandleRefreshToken(userID, &q)
		if err != nil {
			http.Error(w, "Failed to decrypt token", http.StatusInternalServerError)
			return
		}
		config := &oauth2.Config{}
		client := config.Client(ctx, token)
		gmailService, err := gmail.New(client)
		if err != nil {
			log.Printf("failed to create Gmail service: %s", err.Error())
		}
		// Generate persona

		persona, err := library.SentEmailReader(gmailService, user, &q, 50)
		if err != nil {
			log.Println("ERROR GENERATING PERSONA", err)
			http.Error(w, "Failed to generate persona", http.StatusInternalServerError)
		}
		log.Println("PERSONA", persona)
		response := SetPersonaResponse{
			Success: true,
			Message: persona,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

}

func Unlink(q store.Queries) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the request body (assuming JSON)
		var reqBody struct {
			UserID string `json:"user_id"`
		}
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Convert user ID to UUID
		userID, err := uuid.Parse(reqBody.UserID)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		// Unlink the user (implementation depends on your database schema)
		_, err = q.RemoveTokens(r.Context(), userID) // Replace with your query function
		if err != nil {
			// Handle database error appropriately
			http.Error(w, "Failed to unlink user", http.StatusInternalServerError)
			return
		}

		// Respond with success JSON
		response := SetPersonaResponse{
			Success: true,
			Message: "User unlinked successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			// Handle the JSON encoding error
			http.Error(w, "Internal Server Error", http.StatusInternalServerError) // Or a more specific error message
			log.Println("Error encoding JSON response:", err)                      // Log the error for debugging
			return                                                                 // Stop further processing
		}
	}
}
