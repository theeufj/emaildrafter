package middleware

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/csrf"
)

var (
	csrfMiddleware = csrf.Protect(
		[]byte("32-byte-long-auth-key"), // Replace with a strong, randomly generated key
		csrf.Secure(true),               // Set to false in development if not using HTTPS
	)
)
var (
	xForwardedScheme = http.CanonicalHeaderKey("X-Forwarded-Scheme")
	xForwardedProto  = http.CanonicalHeaderKey("X-Forwarded-Proto")
	// RFC7239 defines a new "Forwarded: " header designed to replace the
	// existing use of X-Forwarded-* headers.
	// e.g. Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43.
	forwarded = http.CanonicalHeaderKey("Forwarded")
	// Allows for a sub-match for the first instance of scheme (http|https)
	// prefixed by 'proto='. The match is case-insensitive.
	protoRegex = regexp.MustCompile(`(?i)(?:proto=)(https|http)`)
)

func getScheme(r *http.Request) string {
	// Get the scheme
	scheme := r.URL.Scheme

	// Retrieve the scheme from X-Forwarded-Proto.
	if proto := r.Header.Get(xForwardedProto); proto != "" {
		scheme = strings.ToLower(proto)
	} else if proto = r.Header.Get(xForwardedScheme); proto != "" {
		scheme = strings.ToLower(proto)
	} else if proto = r.Header.Get(forwarded); proto != "" {
		// match should contain at least two elements if the protocol was
		// specified in the Forwarded header. The first element will always be
		// the 'proto=' capture, which we ignore. In the case of multiple proto
		// parameters (invalid) we only extract the first.
		if match := protoRegex.FindStringSubmatch(proto); len(match) > 1 {
			scheme = strings.ToLower(match[1])
		}
	}

	return scheme
}

// httpsForwardMiddleware checks for X-Forwarded-Proto and redirects
// http to https
func HttpsForwardMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := getScheme(r)
		// Check for http
		if scheme != "" {
			r.URL.Scheme = scheme
		}

		if scheme != "https" {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// HSTS Middleware to enforce HTTPS
func HSTS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		next.ServeHTTP(w, r)
	})
}

// ReferrerPolicy Middleware to control Referrer header behavior
func ReferrerPolicy(policy string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Referrer-Policy", policy)
			next.ServeHTTP(w, r)
		})
	}
}

// CSP Middleware to set the Content-Security-Policy header
func CSP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Construct your CSP policy string
		policy := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com; " +
			"img-src 'self' data:; " +
			"frame-src https://accounts.google.com; " +
			"style-src 'self' https://cdn.tailwindcss.com" // Allow Tailwind CDN

		w.Header().Set("Content-Security-Policy", policy)
		next.ServeHTTP(w, r)
	})
}

// ContentTypeOptions Middleware to set the X-Content-Type-Options header
func ContentTypeOptions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders Middleware to set common security headers
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. X-Frame-Options (Clickjacking Protection)
		w.Header().Set("X-Frame-Options", "DENY")

		// 2. Permissions-Policy (Feature Control)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=()") // Customize as needed

		// 3. Cache-Control (Caching for Sensitive Pages)
		if r.URL.Path == "/login" || r.URL.Path == "/account" { // Example paths
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}

		// 4. Content-Security-Policy (CSP)
		// Construct your CSP policy string
		//https://unpkg.com
		policy := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com https://cdn.tailwindcss.com; " + // Removed unpkg.com from script-src
			"img-src 'self' data:; " +
			"frame-src https://accounts.google.com; " +
			"style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline' https://use.fontawesome.com https://fonts.googleapis.com https://unpkg.com;" + // Added fonts.googleapis.com for Google Fonts
			"font-src 'self' https://use.fontawesome.com fonts.gstatic.com;" // Maintains font-src directive// Maintains font-src directive
		w.Header().Set("Content-Security-Policy", policy)

		// 5. Referrer-Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 6. X-Content-Type-Options (MIME-Sniffing Protection)
		w.Header().Set("X-Content-Type-Options", "nosniff")

		next.ServeHTTP(w, r)
	})
}

func CSRFProtect(next http.Handler) http.Handler {
	return csrfMiddleware(next)
}

func MicrosoftIdentityAssociationHandler(w http.ResponseWriter, r *http.Request) {
	association := map[string]interface{}{
		"associatedApplications": []map[string]string{
			{
				"applicationId": "0adae431-82c7-4539-8aad-ac6d6351a7f9",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(association)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
