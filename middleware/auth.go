package middleware

import (
	"log"
	"net/http"
	"time"

	"emaildrafter/internal/flash"
	// Import the package where datastore is defined
	// Assuming this is the correct path
)

//

// LoggedInMiddleware checks if a user is logged in and redirects to the login page if not.
func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		log.Println(sid)

		//Retrieve the session from database, if the session is expiered redirect to login page
		// if no session is found return to landing page
		if err != nil {
			flash.Set(w, flash.Warning, "Error", err.Error())
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// User is logged in, proceed to the next handler
		next.ServeHTTP(w, r)
	})
}

// AuthMiddleware checks if the "loggedIn" cookie is set to "true" and not expired.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggedInCookie, err := r.Cookie("loggedIn")
		if err != nil || loggedInCookie.Value == "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Check if the cookie has expired based on its creation time
		if loggedInCookie.MaxAge > 0 {
			creationTime := time.Now().Add(time.Duration(-loggedInCookie.MaxAge) * time.Second)
			if time.Now().After(creationTime.Add(time.Duration(loggedInCookie.MaxAge) * time.Second)) {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
