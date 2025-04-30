package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"netsocial/middlewares"
	"netsocial/routes"
	"netsocial/types"
	"os"
	"os/signal"
	"strconv"
	"time"

	"netsocial/database"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/goccy/go-yaml"
)

var configuration types.Config

func main() {
	ConfigHandler()

	port := configuration.Port

	log.Printf("[Harbinger] Running in %s environment with port: %s", configuration.Environment, strconv.Itoa(port))

	PsqlURL := configuration.PsqlURL
	RedisURL := configuration.RedisURL

	// Connect to database and defer disconnect
	var db *database.Database
	var err error
	db, err = database.Connect(PsqlURL, RedisURL, "seed", "backups")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Disconnect(db)

	// Setup router and server
	r := setupRouter(db)

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: r,
	}

	if configuration.Environment == "production" && configuration.Algor.RunModel {
		middlewares.Algor()
	}

	// Graceful shutdown
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	Gracey(srv)
}

func setupRouter(db *database.Database) *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
	}))

	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.CleanPath)
	r.Use(middleware.Logger)
	//r.Use(csrf.Protect([]byte(configuration.CsrfKey), csrf.Secure(true)))
	r.Use(middleware.RequestID)

	// Attach database middleware
	r.Use(database.Middleware(db))
	r.Use(middlewares.DiscordErrorReport)

	// Set up worker pool
	r.Use(middleware.Throttle(configuration.Workers))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message":     "Hello, World from Net Social!",
			"version":     configuration.ApiVersion,
			"enviornment": configuration.Environment,
			"Author":      "Harbingers of your destiny",
			"links": map[string]string{
				"status":  "https://netsocial.instatus.com",
				"website": "https://netsocial.app",
				"docs":    "https://docs.netsocial.app",
			},
			"license": map[string]string{
				"name":       "GNU Affero General Public License v3.0",
				"learn more": "https://opensource.org/license/gpl-3-0",
			},
			"support": map[string]string{
				"email":   "support@netsocial.app",
				"discord": "https://discord.com/invite/DcUX2pMta4",
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

	//Notification
	routes.Notification(r)

	// Coterie
	routes.CoterieRoutes(r)

	// Authentication
	routes.Auth(r)

	// Misc routes
	routes.Stats(r)
	routes.Blogs(r)
	routes.Partner(r)

	r.NotFound(NotFoundHandler)

	r.Get("/openapi", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./openapi.json")
	})

	r.Get("/docs", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<!doctype html>
			<html lang="en">
				<head>
				<meta charset="utf-8">
				<title>NetSocial Internal API Docs -Elements</title>
				<link rel="stylesheet" href="https://unpkg.com/@stoplight/elements/styles.min.css">
				</head>
				<body>
				<script src="https://unpkg.com/@stoplight/elements/web-components.min.js"></script>
				<elements-api
					apiDescriptionUrl="/openapi"
					layout="sidebar"
					logo="https://netsocial.app/assets/img/logo.png"
				>
				</elements-api>
				</body>
			</html>
			`))
	})

	return r
}

func respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusNotFound, map[string]string{
		"message": "Woah, Chief! Looks like you are in an uncharted territory!",
	})
}

func ConfigHandler() {
	if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
		log.Println("[Harbinger] config.yaml not found. Creating a new config file...")
		newconf := types.Config{}
		middlewares.MakeConfig(newconf, "config.yaml")
		log.Println("[Harbinger] config.yaml created successfully. Please configure it before running the server.")
		os.Exit(0)
	} else {
		configFile, err := ioutil.ReadFile("config.yaml")
		if err != nil {
			log.Fatalf("[Harbinger] Failed to read config file: %v", err)
		}
		err = yaml.UnmarshalWithOptions(configFile, &configuration, yaml.DisallowUnknownField())
		if err != nil {
			log.Fatalf("[Harbinger] Failed to parse config file: %v", err)
		}
	}

	// Perform additional server side config checks
	if configuration.Environment == "production" {
		log.Println("[Harbinger] Performing additional server requirement checks...")
		ConfigChecks()
	}

	// Check for OpenAPI file and create if not exists
	if _, err := os.Stat("openapi.json"); os.IsNotExist(err) {
		log.Println("[Harbinger] openapi.json not found. Creating a new OpenAPI file...")
		openAPIContent := `{
			"openapi": "3.0.0",
			"info": {
				"title": "NetSocial API",
				"description": "API documentation for NetSocial",
				"version": "` + configuration.ApiVersion + `",
				"contact": {
					"name": "Support Team",
					"email": "support@netsocial.app"
				}
			},
			"servers": [
				{
					"url": "https://api.netsocial.app",
					"description": "Production Server"
				},
				{
					"url": "http://localhost:` + strconv.Itoa(configuration.Port) + `",
					"description": "Local Development Server"
				}
			]
		}`

		if err := ioutil.WriteFile("openapi.json", []byte(openAPIContent), 0644); err != nil {
			log.Fatalf("[Harbinger] Failed to write openapi.json: %v", err)
		}
		log.Println("[Harbinger] openapi.json created successfully.")
	}
}

func ConfigChecks() {
	if configuration.Port < 1024 || configuration.Port > 65535 {
		log.Fatal("[Harbinger] Invalid port number. Please configure a port between 1024 and 65535.")
	}

	if configuration.Workers < 1 || configuration.Workers > 100 {
		log.Fatal("[Harbinger] Insufficient worker threads for scalability. Configure between 1 and 100.")
	}

	if configuration.PsqlURL == "" {
		log.Fatal("[Harbinger] No PostgreSQL URL provided. Please check config.yaml.")
	}

	if configuration.AESKey == "" {
		log.Fatal("[Harbinger] No AES key provided. Please check config.yaml.")
	} else if len(configuration.AESKey) != 32 {
		log.Fatal("[Harbinger] Invalid AES key length. Must be 32 characters long.")
	}

	if configuration.Environment != "production" && configuration.Environment != "development" {
		log.Fatal("[Harbinger] Environment not specified or invalid. Please set the environment in config.yaml to either 'development' or 'production'.")
	}

	if configuration.ApiVersion == "" {
		log.Fatal("[Harbinger] API version not specified. Please set the API version in config.yaml.")
	}

	//if configuration.Environment == "production" && configuration.Algor.OllamaURL == "" {
	//    log.Fatal("[Harbinger] ollama url not configured. Please set the it in config.yaml.")
	//}

	log.Println("[Harbinger] Server requirement checks passed successfully.")
}

func Gracey(srv *http.Server) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	log.Println("[Gracey] Received shutdown signal, initiating gracey sequence...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[Gracey] Error during shutdown: %v", err)
		log.Println("[Gracey] Forcing Harbinger shutdown...")
		if err := srv.Close(); err != nil {
			log.Fatalf("[Gracey] Error during forced shutdown: %v", err)
		}
	}

	log.Println("[Gracey] Harbinger has been shut down successfully")
}
