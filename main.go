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
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

var (
	logger  *slog.Logger
	queries *store.Queries
)

func main() {
	if err := env.LoadFromFile(".env"); err != nil {
		log.Fatalf("Failed to load .env file: %v", err)
	}

	port := env.GetAsStringElseAlt("PORT", "9005")
	mode := env.GetAsStringElseAlt("ENV", "dev")

	setupLogger(mode)

	r := setupRouter()

	dbHost := getDBHost(mode)
	db, err := setupDatabase(dbHost)
	if err != nil {
		logger.Error("Failed to setup database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	queries = store.New(db)

	setupRoutes(r)

	go runPeriodicDrafter()

	server := createServer(r, mode, port)
	CSRF := csrf.Protect(
		[]byte("32-byte-long-auth-key"),
		csrf.Secure(true),
		csrf.ErrorHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "CSRF token invalid", http.StatusForbidden) // Custom error handling for invalid CSRF tokens
		})),
	)

	// Wrap the entire router with CSRF protection
	http.Handle("/", CSRF(r))
	logger.Info("Your app is running", "host", server.Addr)

	log.Fatal(server.ListenAndServeTLS("", ""))
}

type multiHandler struct {
	handlers []slog.Handler
}

// Handle implements slog.Handler.
func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if err := h.Handle(ctx, r); err != nil {
			return err // You might want to handle errors differently here
		}
	}
	return nil
}

// Enabled implements slog.Handler.
func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	// If any handler is enabled for this level, return true
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// WithAttrs implements slog.Handler.
func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

// WithGroup implements slog.Handler.
func (m *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

func setupLogger(mode string) {
	// Create a shared options struct for all handlers
	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug, // Debug level for development
	}

	// Create a text handler for console output
	consoleHandler := slog.NewTextHandler(os.Stdout, opts)

	// Create a file for logging
	logFile, err := os.OpenFile("app.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(1)
	}

	// Create a JSON handler for file output
	fileHandler := slog.NewJSONHandler(logFile, opts)

	// Adjust log levels based on mode
	if mode == "prod" {
		opts.Level = slog.LevelInfo // Reduce log level for production
	}
	// Create a multi-handler that writes to both console and file
	multiHandler := &multiHandler{
		handlers: []slog.Handler{consoleHandler, fileHandler},
	}

	// Create the logger with the multi-handler
	logger = slog.New(multiHandler)

	logger.Info("Logging setup complete", "mode", mode)
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(cacheControlMiddleware)
	return r
}

func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=0, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func getDBHost(mode string) string {
	if mode == "dev" {
		return "postgres://postgres:jc194980!@ec2-13-210-207-191.ap-southeast-2.compute.amazonaws.com:5432/emaildrafterDev"
	}
	// TODO: Modify this for production database
	return "postgres://postgres:jc194980!@ec2-13-210-207-191.ap-southeast-2.compute.amazonaws.com:5432/emaildrafter"
}

func setupDatabase(dbHost string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dbHost)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func setupRoutes(r *mux.Router) {
	r.Use(middleware.HSTS)
	r.Use(middleware.SecurityHeaders)
	r.Handle("/setpersona",
		middleware.CSRFProtect( // Wrap with CSRF middleware
			http.HandlerFunc(SetPersonas(*queries)), // Your handler
		),
	).Methods("POST")

	r.Handle("/generatepersona",
		middleware.CSRFProtect( // Wrap with CSRF middleware
			http.HandlerFunc(GeneratePersona(*queries)), // Your handler
		),
	).Methods("POST")

	fs := http.FileServer(http.Dir("static"))
	r.PathPrefix("/static").Handler(http.StripPrefix("/static", fs))

	r.Handle("/notifications", flash.HandlerWithLogger(logger))

	r.HandleFunc("/flash", flashHandler)
	r.HandleFunc("/", catchAllAndRouteToStatic())
	r.HandleFunc("/terms_of_use", catchAllAndRouteToStatic())
	r.HandleFunc("/Privacy_Policy_v2", catchAllAndRouteToStatic())

	r.HandleFunc("/login", ServeLoginPage)
	// google login
	r.HandleFunc("/login/auth", middleware.LoginHandler)
	r.HandleFunc("/login/callback", callbackHandler)
	// microsoft login
	r.HandleFunc("/login/microsoft", middleware.LoginHandlerMicrosoft)
	r.HandleFunc("/login/microsoft/callback", middleware.CallbackHandlerMicrosoft)
	// a path too https://aidrafter.xyz/.well-known/microsoft-identity-association.json
	r.HandleFunc("/.well-known/microsoft-identity-association.json", middleware.MicrosoftIdentityAssociationHandler)

	r.Handle("/admin", middleware.AuthMiddleware(http.HandlerFunc(AdminHandler(*queries)))).Methods("GET")

	r.HandleFunc("/unlink", Unlink(*queries)).Methods("POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("GET")
}

func flashHandler(w http.ResponseWriter, r *http.Request) {
	flash.Set(w, flash.Success, "Flash Handler Test! ", "High five 🖐️")
	http.Redirect(w, r, "/", http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	middleware.CallbackHandler(w, r, queries)
}

func runPeriodicDrafter() {
	logger.Info("Starting Drafter")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		users, err := queries.GetAllUsers(context.Background())
		if err != nil {
			logger.Error("Failed to get users", "error", err)
			continue
		}

		for _, user := range users {
			if user.Refreshtoken.Valid {
				if err := Drafter(*queries, user.ID); err != nil {
					logger.Error("Failed to run drafter", "userID", user.ID, "error", err)
				} else {
					logger.Info("Successfully ran drafter for user", "userID", user.ID)
				}
			} else {
				logger.Info("User does not have a valid refresh token", "userID", user.ID)
			}
		}
	}
}

func createServer(r *mux.Router, mode, port string) *http.Server {
	var certFile, keyFile string
	if mode == "dev" {
		certFile, keyFile = "cert.pem", "key.pem"
	} else {
		certFile = "/etc/letsencrypt/live/www.aidrafter.xyz/fullchain.pem"
		keyFile = "/etc/letsencrypt/live/www.aidrafter.xyz/privkey.pem"
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		logger.Error("Error loading certificate and key", "error", err)
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
	}
}

func Drafter(queries store.Queries, userID uuid.UUID) error {
	token, err := middleware.HandleRefreshToken(userID, &queries)
	if err != nil {
		logger.Error("Failed to handle refresh token", "userID", userID, "error", err)
		return err
	}

	user, err := queries.GetUserByID(context.Background(), userID)
	if err != nil {
		logger.Error("Failed to get user by ID", "userID", userID, "error", err)
		return err
	}

	logger.Info("Composing email for user", "userID", userID)
	return library.GmailCompose(token, user, &queries)
}
