package main

import (
	"database/sql"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
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
	tmpl.Execute(w, nil)
}

func AdminHandler(q store.Queries) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// get the user by their google id, which is found in the loggedIn cookie
		cookie, err := r.Cookie("loggedIn")
		if err != nil {
			log.Println(err)
		}
		user, err := q.GetUserByGoogleID(r.Context(), cookie.Value)
		log.Println(user.Persona)
		if err != nil {
			log.Println(err)
		}
		csrfToken := csrf.Token(r)
		logs, err := q.GetLogsByUserID(r.Context(), user.ID)
		if err != nil {
			err = portal.Execute(w, nil)
		} else {
			// create a map of user and logs
			data := map[string]interface{}{
				"User":      user,
				"Logs":      logs,
				"csrfToken": csrfToken,
			}
			err = portal.Execute(w, data)
		}
		if err != nil {
			http.Error(w, "Error rendering template", http.StatusInternalServerError)
			log.Printf("Error executing template: %v", err)
		}
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
		var reqBody struct {
			UserID  string `json:"user_id"`
			Persona string `json:"persona`
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

		// Update the persona in the database
		_, err = q.SetPersona(r.Context(), store.SetPersonaParams{
			Persona: sql.NullString{
				String: reqBody.Persona,
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
		json.NewEncoder(w).Encode(response)
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
		json.NewEncoder(w).Encode(response)
	}
}
