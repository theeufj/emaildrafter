package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"emaildrafter/database/store"
	"emaildrafter/internal/env"
	"emaildrafter/internal/flash"
	"emaildrafter/internal/library"
	"emaildrafter/middleware"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var (
	logger  *slog.Logger
	queries *store.Queries
)

func main() {
	env.LoadFromFile(".env")
	port := env.GetAsStringElseAlt("PORT", "9005")
	mode := env.GetAsStringElseAlt("ENV", "dev")
	log.SetFlags(log.LstdFlags | log.Lshortfile) // Include file and line number
	log.SetOutput(os.Stdout)                     // Send logs to standard output

	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug, // we toggle this if we're in prod
	}
	var handler slog.Handler = slog.NewTextHandler(os.Stdout, opts)
	if mode == "prod" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	logger = slog.New(handler)

	r := mux.NewRouter()

	var dbHost string
	if mode == "dev" {
		dbHost = "postgres://joshtheeuf:jc194980@localhost:5432/emaildrafter?sslmode=disable"
	} else {
		// this needs to be modified for prod db
		dbHost = "postgres://postgres:jc194980!@ec2-13-210-207-191.ap-southeast-2.compute.amazonaws.com:5432/emaildrafter"
	}
	// setup a database handler queries
	db, dbConnectionError := sql.Open("postgres", dbHost)
	if dbConnectionError != nil {
		logger.Error("Error connecting to host", "error", dbConnectionError)
	}
	ctx := context.Background()
	err := db.PingContext(ctx)
	if err != nil {
		logger.Error("Error pinging host", "error", err.Error())
	}

	queries = store.New(db)

	// Set caching preference
	// Could use Cache-Control: no-store
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {
			wr.Header().Set("Cache-Control", "max-age=0, must-revalidate")
			next.ServeHTTP(wr, req)
		})
	})

	// Setup static file handling
	fs := http.FileServer(http.Dir("static"))
	r.PathPrefix("/static").Handler(http.StripPrefix("/static", fs))

	// Setup the Flash package notification handler
	r.Handle("/notifications", flash.HandlerWithLogger(logger))

	r.HandleFunc("/flash", func(w http.ResponseWriter, r *http.Request) {
		flash.Set(w, flash.Success, "Flash Handler Test! ", "High five 🖐️")
		http.Redirect(w, r, "/", http.StatusFound)
	})

	// Entry route
	r.HandleFunc("/", catchAllAndRouteToStatic())
	r.HandleFunc("/terms_of_use", catchAllAndRouteToStatic())
	r.HandleFunc("/Privacy_Policy_v2", catchAllAndRouteToStatic())
	log.Println(env.GetAsString("OAUTH"))

	r.HandleFunc("/login", ServeLoginPage)
	r.HandleFunc("/login/auth", middleware.LoginHandler)
	r.HandleFunc("/login/callback", func(w http.ResponseWriter, r *http.Request) {
		middleware.CallbackHandler(w, r, queries)
	})
	// Login protected paths
	r.HandleFunc("/admin", AdminHandler(*queries)).Methods("GET").Handler(middleware.AuthMiddleware(http.HandlerFunc(AdminHandler(*queries))))
	// set the persona
	r.HandleFunc("/setpersona", SetPersonas(*queries)).Methods("POST")
	// unlink the gmail account
	r.HandleFunc("/unlink", Unlink(*queries)).Methods("POST")
	
	r.HandleFunc("/logout", LogoutHandler).Methods("GET")

	// We need to trigger Drafter every 15 minuutes as a go routine
	go func() {
		for {
			// get all users
			users, err := queries.GetAllUsers(context.TODO())
			if err != nil {
				log.Println(err)
			}
			// loop through users and call the drafter function
			for _, user := range users {
				//only if there is a refresh token for the user do we run this
				if user.Refreshtoken.Valid {
					Drafter(*queries, user.ID)
				}
			}
			// sleep for 15 minutes
			time.Sleep(15 * time.Minute)
		}
	}()

	if mode == "dev" {
		cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
		if err != nil {
			logger.Error("Error loading certificate and key", "error", err)
			return
		}

		// Create a TLS configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Create a server with the TLS configuration
		server := &http.Server{
			Addr:      ":8080", // Or your desired port
			Handler:   r,
			TLSConfig: tlsConfig,
		}

		// Start the server
		logger.Info("Your app is running on", "host", "https://localhost:8080")
		log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem")) // Serve TLS with correct file paths
	} else {
		cert, err := tls.LoadX509KeyPair("/etc/letsencrypt/live/www.aidrafter.xyz/fullchain.pem", "/etc/letsencrypt/live/www.aidrafter.xyz/privkey.pem")
		if err != nil {
			logger.Error("Error loading certificate and key", "error", err)
			return
		}

		// Create a TLS configuration
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		// Create a server with the TLS configuration
		server := &http.Server{
			Addr:      ":" + port, // Or your desired port
			Handler:   r,
			TLSConfig: tlsConfig,
		}

		// Start the server
		logger.Info("Your app is running on", "host", "https://aidrafter.xyz")
		log.Fatal(server.ListenAndServeTLS("/etc/letsencrypt/live/www.aidrafter.xyz/fullchain.pem", "/etc/letsencrypt/live/www.aidrafter.xyz/privkey.pem")) // Serve TLS with correct file paths
	}
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	// just show "Hello, World!" for now
	_, _ = w.Write([]byte("Hello, World!"))
}

// This function will handle calling the gmail compose task, as well as refresh the token
func Drafter(queries store.Queries, user_id uuid.UUID) {
	err, Token := middleware.HandleRefreshToken(user_id, queries)
	if err != nil {
		log.Println(err)
	}
	// get the user by their user_id
	user, err := queries.GetUserByID(context.TODO(), user_id)
	if err != nil {
		log.Println(err)
	}
	// compose the last group of emails
	library.GmailCompose(Token, user)

}
