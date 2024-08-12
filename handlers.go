package main

import (
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"html/template"
	"log"
	"net/http"
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
		default:
			http.ServeFile(w, r, "static/"+r.URL.Path+".html")
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
		if err != nil {
			log.Println(err)
		}
		logs, err := q.GetLogsByUserID(r.Context(), user.ID)
		if err != nil {
			err = portal.Execute(w, nil)
		} else {
			// create a map of user and logs
			data := map[string]interface{}{
				"User": user,
				"Logs": logs,
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
