package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"netsocial/configuration"
	"netsocial/database"
	"netsocial/routes"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
)

type contextKey string

const dbContextKey contextKey = "db"

func main() {
	// Load environment variables
	loadEnv()

	// Fetch environment variables
	dbURL := getEnv("DATABASE_URL")
	port := getEnv("PORT")

	// Create a new Chi router
	r := setupRouter(dbURL)

	// Create a server
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}

// Load environment variables from .env file
func loadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found or could not be loaded.")
	}
}

// Get environment variable or log fatal error if not set
func getEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("%s environment variable not set", key)
	}
	return value
}

// Setup router with middleware and routes
func setupRouter(dbURL string) *chi.Mux {
	r := chi.NewRouter()

	// CORS Middleware using go-chi/cors
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
	}))

	// Middleware: Recovery, Database Connection
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.CleanPath)
	r.Use(middleware.Logger)
	r.Use(middleware.AllowContentType("application/json"))

	// Middleware: Database Connection
	db, err := database.Connect(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer func() {
		if err := database.Disconnect(db); err != nil {
			log.Println("Error closing database connection:", err)
		}
	}()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), dbContextKey, db))
			next.ServeHTTP(w, r)
		})
	})

	// Define routes without rate limiting first
	// Home route
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Hello, World from Net Social!",
			"version": configuration.GetConfig().ApiVersion,
			"links": map[string]string{
				"status": "https://netsocial.instatus.com",
				"docs":   "https://docs.netsocial.app",
			},
		})
	})

	// Post Routes
	r.Get("/link/extract", routes.ExtractLinkPreview)
	routes.PostRoutes(r)

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
	routes.Blogs(r)
	routes.Partner(r)
	r.NotFound(NotFoundHandler)

	return r
}

// Helper function to respond with JSON
func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// Custom 404 Not Found handler
func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusNotFound, map[string]string{
		"message": "Woah, Chief! Looks like you are in an uncharted territory!",
	})
}
