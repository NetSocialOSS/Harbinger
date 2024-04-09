package main

import (
	"log"
	"os"

	"netsocial/configuration"
	"netsocial/database"
	"netsocial/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/joho/godotenv"
	"github.com/ravener/discord-oauth2"
	"golang.org/x/oauth2"
)

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Create Fiber app instance
	app := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "NetSocial",
		AppName:       "A social media website.",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Println("Error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal Server Error",
			})
		},
	})

	// Middleware: CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type, Origin, X-Requested-With, Accept,x-client-key, x-client-token, x-client-secret, authorization",
		AllowCredentials: false,
	}))

	// Middleware: Database Connection
	db, err := database.Connect(os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Disconnect(nil)
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("db", db)
		return c.Next()
	})

	// Middleware: Session
	store := session.New()
	app.Use(func(c *fiber.Ctx) error {
		sess, _ := store.Get(c)
		c.Locals("session", sess)
		return c.Next()
	})

	// Middleware: OAuth2 Configuration
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("authConfig", &oauth2.Config{
			RedirectURL:  configuration.GetConfig().Client.Callback,
			ClientID:     configuration.GetConfig().Client.Id,
			ClientSecret: os.Getenv("CLIENT_SECRET"),
			Scopes:       []string{discord.ScopeIdentify},
			Endpoint:     discord.Endpoint,
		})
		return c.Next()
	})

	// Routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Hello, World!",
			"version": "2.0.0",
			"author":  "Ranveer Soni",
			"links": fiber.Map{
				"status": "https://status.netsocial.us",
				"docs":   "https://docs.netsocial.us/",
			},
		})
	})

	//Shared
	app.Get("/auth/login", routes.Login)
	app.Get("/auth/callback", routes.Callback)
	app.Get("/auth/logout", routes.Logout)
	app.Get("/auth/@me", routes.GetCurrentUser)

	// Listen and serve
	port := configuration.GetConfig().Web.Port
	log.Fatal(app.Listen(":" + port))
}
