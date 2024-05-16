package main

import (
	"log"
	"os"

	"socialflux/configuration"
	"socialflux/database"
	"socialflux/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/joho/godotenv"
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
		ServerHeader:  "SocialFlux",
		AppName:       "Share Your Post with the World at SocialFlux",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Println("Error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal Server Error",
			})
		},
	})

	// Middleware: CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000,https://socialflux.xyz,https://netsocial.app,https://net-social-website.vercel.app,https://beta.netsocial.app", // Allow requests from your frontend origin
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type, Origin, X-Requested-With, Accept,x-client-key, x-client-token, x-client-secret, authorization",
		AllowCredentials: true, // Allow credentials (cookies, authorization headers, etc.)
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

	// Routes
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Hello, World!",
			"version": "2.0.0",
			"author":  "Ranveer Soni",
			"links": fiber.Map{
				"status": "https://status.netsocial.app",
				"docs":   "https://docs.netsocial.app/",
			},
		})
	})

	//Partner
	app.Get("/stats/partners/@all", routes.TotalPartnersCount)

	//Users
	app.Get("/stats/users/@all", routes.RegistergedUserNum)
	app.Get("/user/:username", routes.GetUserByName)
	app.Get("/profile/:userId/image", routes.ProfilePictureHandler)
	app.Get("/profile/:userId/banner", routes.ProfileBannerHandler)

	//Post
	app.Get("/posts/@all", routes.GetAllPosts)
	app.Get("/posts/:id", routes.GetPostById)

	//MISC
	app.Get("/blog/posts/@all", routes.GetPosts)
	app.Get("/partners/@all", routes.GetAllPartner)

	// Listen and serve
	port := configuration.GetConfig().Web.Port
	log.Fatal(app.Listen(":" + port))
}
