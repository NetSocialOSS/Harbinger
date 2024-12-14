package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"netsocial/configuration"
	"netsocial/database"
	"netsocial/routes"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
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

	// Create a new Chi router
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

	// Listen and serve
	port := configuration.GetConfig().Web.Port
	log.Fatal(http.ListenAndServe(":"+port, r))
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
