package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"netsocial/configuration"
	"netsocial/database"
	"netsocial/routes"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

func main() {
	// Attempt to load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found or could not be loaded.")
	}

	// Fetch environment variables, fallback to environment directly if needed
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL environment variable not set")
	}

	// Additional environment variables (if needed)
	discordWebhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if discordWebhookURL == "" {
		log.Println("DISCORD_WEBHOOK_URL environment variable not set")
	}

	// Create a new Chi router
	r := chi.NewRouter()

	// CORS Middleware using go-chi/cors
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
	}))

	// Middleware: Recovery, Database Connection
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.CleanPath)
	r.Use(middleware.AllowContentType("application/json"))

	// Middleware: Database Connection
	db, err := database.Connect(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Disconnect(nil)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), "db", db))
			next.ServeHTTP(w, r)
		})
	})

	// Define routes without rate limiting first
	// Home route
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Hello, World from Net Social!",
			"version": configuration.GetConfig().ApiVersion,
			"author":  "Ranveer Soni",
			"links": map[string]string{
				"status": "https://status.netsocial.app",
				"docs":   "https://docs.netsocial.app",
			},
		})
	})

	// Post Routes
	r.Get("/posts/@all", routes.GetAllPosts)
	r.Get("/link/extract", routes.ExtractLinkPreview)
	r.Get("/posts/{id}", routes.GetPostById)
	r.With(rateLimitMiddleware(5, 5*time.Minute)).Post("/comment/add", routes.AddComment)
	r.With(rateLimitMiddleware(5, 5*time.Minute)).Post("/post/action", routes.PostActions)
	r.With(rateLimitMiddleware(5, 5*time.Minute)).Delete("/post/delete", routes.DeletePost)
	r.With(rateLimitMiddleware(5, 5*time.Minute)).Post("/post/add", routes.AddPost)

	// Admin
	routes.Admin(r)

	// Havok Chat
	routes.HavokRoutes(r)

	// Report
	routes.Report(r)

	// Users
	routes.User(r)

	// Coterie
	routes.CoterieRoutes(r)

	// Authentication
	routes.Auth(r)

	// Misc routes
	routes.Stats(r)
	r.Get("/blog/posts/@all", routes.GetPosts)
	r.Get("/partners/@all", routes.GetAllPartner)

	// Listen and serve
	port := configuration.GetConfig().Web.Port
	log.Fatal(http.ListenAndServe(":"+port, r))
}

// Rate Limit Middleware
func rateLimitMiddleware(limit int, burst time.Duration) func(http.Handler) http.Handler {
	// Create a rate limiter
	limiter := rate.NewLimiter(rate.Every(burst/time.Duration(limit)), limit)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter.Allow() {
				next.ServeHTTP(w, r)
			} else {
				// Rate limit exceeded, return a custom message
				w.WriteHeader(http.StatusTooManyRequests) // Set status code to 429
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("Woah! Slow down bucko! You're being rate limited!"))
			}
		})
	}
}

// Helper function to respond with JSON
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}
