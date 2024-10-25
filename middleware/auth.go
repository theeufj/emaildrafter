package middleware

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"emaildrafter/internal/env"
	"emaildrafter/internal/flash"

	"github.com/golang-jwt/jwt/v4"
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

var jwtSigningKey []byte
var jwtSessionLengthMinutes time.Duration = 15
var jwtSigningMethod = jwt.SigningMethodHS256

type JWTValues map[string]string

// Get gets the first value associated with the given key.
func (v JWTValues) Get(key string) string {
	if v == nil {
		return ""
	}
	vs := v[strings.ToLower(key)]
	if len(vs) == 0 {
		return ""
	}
	return vs
}

// Set sets the key to value. It replaces any existing
// values.
func (v JWTValues) Set(key, value string) {
	v[strings.ToLower(key)] = value
}

type CustomClaims struct {
	Vars JWTValues
	jwt.RegisteredClaims
}

func init() {
	jwtSigningKey = []byte(env.GetAsString("JWT_SIGNING_KEY"))
}

func CreateJWTTokenForUser(v JWTValues) string {
	claims := CustomClaims{
		v,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * jwtSessionLengthMinutes)),
		},
	}

	// Encode to token string
	tokenString, err := jwt.NewWithClaims(jwtSigningMethod, claims).SignedString(jwtSigningKey)
	if err != nil {
		log.Println("Error occurred generating JWT", err)
		return ""
	}
	return tokenString
}

func DecodeJWTToUser(token string) (JWTValues, error) {
	// Decode
	decodeToken, err := jwt.ParseWithClaims(token, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if !(jwtSigningMethod == token.Method) {
			// Check our method hasn't changed since issuance
			return nil, fmt.Errorf("signing method mismatch")
		}
		return jwtSigningKey, nil
	})

	// GTFO
	if err != nil {
		return JWTValues{}, err
	}

	// There's two parts. We might decode it successfully but it might
	// be the case we aren't Valid so you must check both
	if decClaims, ok := decodeToken.Claims.(*CustomClaims); ok && decodeToken.Valid {
		return decClaims.Vars, nil
	}

	return JWTValues{}, err
}
