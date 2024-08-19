package routes

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"netsocial/types"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/golang-jwt/jwt"
	"github.com/gtuk/discordwebhook"
	"github.com/resend/resend-go/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = generateRandomString(286)

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length]
}

func generateJWT(userID primitive.ObjectID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.Hex(),
		"exp":     time.Now().Add(time.Hour * 7628).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func authMiddleware(c *fiber.Ctx) error {
	tokenStr := c.Cookies("token")
	if tokenStr == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.NewError(fiber.StatusUnauthorized, "Invalid token")
		}
		return []byte(jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
	}

	userID, err := primitive.ObjectIDFromHex(claims["user_id"].(string))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
	}

	c.Locals("user_id", userID)
	return c.Next()
}

func FetchDisposableDomains() (map[string]bool, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	disposableDomains := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		domain := scanner.Text()
		disposableDomains[domain] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return disposableDomains, nil
}

func sendWelcomeEmail(email string) error {
	apiKey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apiKey)
	params := &resend.SendEmailRequest{
		From:    "Netsocial <welcome@netsocial.app>",
		To:      []string{email},
		Subject: "Welcome to Netsocial!",
		Text:    "Hey, welcome to Netsocial! Let's start by making your first post. [Post Now!](https://netsocial.app/post)",
	}
	_, err := client.Emails.Send(params)
	return err
}

func UserSignup(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	username := c.Query("username")
	email := c.Query("email")
	password := c.Query("password")

	if username == "" || email == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	disposableDomains, err := FetchDisposableDomains()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch disposable email domains"})
	}

	emailParts := strings.Split(email, "@")
	if len(emailParts) != 2 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid email format"})
	}

	emailDomain := emailParts[1]
	if _, exists := disposableDomains[emailDomain]; exists {
		err = sendDiscordWebhookFailure(username, email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send Discord webhook"})
		}

		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Disposable email domains are not allowed"})
	}

	count, err := userCollection.CountDocuments(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": username},
			{"email": email},
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}
	if count > 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Username or email already exists"})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	var lastUser types.User
	err = userCollection.FindOne(context.TODO(), bson.M{}, options.FindOne().SetSort(bson.D{{"userid", -1}})).Decode(&lastUser)
	if err != nil && err != mongo.ErrNoDocuments {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to retrieve last user"})
	}

	newUserID := lastUser.UserID + 1

	user := types.User{
		UserID:         newUserID,
		Username:       username,
		DisplayName:    username,
		IsVerified:     false,
		IsOrganisation: false,
		IsDeveloper:    false,
		IsOwner:        false,
		IsPartner:      false,
		Email:          email,
		Links:          []string{},
		Password:       string(hashedPassword),
		CreatedAt:      time.Now(),
	}

	result, err := userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	_, err = userCollection.UpdateOne(context.TODO(), bson.M{"_id": result.InsertedID}, bson.M{
		"$set": bson.M{"id": result.InsertedID},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update user id"})
	}

	err = sendWelcomeEmail(email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send email. Please check your email address and try again"})
	}

	err = sendDiscordWebhook(username)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to send Discord webhook"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
	})
}

func sendDiscordWebhook(username string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	content := "A new user has registered by the name: " + username
	message := discordwebhook.Message{
		Content: &content,
	}

	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
		return err
	}

	return nil
}

func sendDiscordWebhookFailure(username, email string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	content := fmt.Sprintf("User registration failed for username: %s with email: %s (Disposable email domain)", username, email)
	message := discordwebhook.Message{
		Content: &content,
	}

	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
		return err
	}

	return nil
}

func UserLogin(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	usernameOrEmail := c.Query("usernameOrEmail")
	password := c.Query("password")

	if usernameOrEmail == "" || password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": usernameOrEmail},
			{"email": usernameOrEmail},
		},
	}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	token, err := generateJWT(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    token,
		HTTPOnly: true,
		Secure:   true,
		SameSite: "None",
	})

	err = sendDiscordWebhookLogin(user.Username)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
	}

	return c.JSON(fiber.Map{"message": "Logged in successfully", "user_id": user.ID.Hex()})
}

func sendDiscordWebhookLogin(username string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	content := "User logged in: " + username
	message := discordwebhook.Message{
		Content: &content,
	}

	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		return err
	}

	return nil
}

func UserLogout(c *fiber.Ctx) error {
	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   true,
		SameSite: "None",
	})

	return c.JSON(fiber.Map{"message": "Logged out successfully"})
}

func CurrentUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	// Extract user ID from JWT claims (should be a primitive.ObjectID)
	userID, ok := c.Locals("user_id").(primitive.ObjectID)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to find user"})
	}

	return c.JSON(fiber.Map{
		"_id":         user.ID,
		"username":    user.Username,
		"displayname": user.DisplayName,
	})
}

func ChangePassword(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	// Extract user ID from JWT claims (should be a primitive.ObjectID)
	userID, ok := c.Locals("user_id").(primitive.ObjectID)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid user ID"})
	}

	// Get old password, new password, and confirmation from the query parameters
	oldPassword := c.Query("old_password")
	newPassword := c.Query("new_password")
	confirmPassword := c.Query("confirm_password")

	if oldPassword == "" || newPassword == "" || confirmPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Missing required fields"})
	}

	// Check if the new password meets the minimum length requirement
	if len(newPassword) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "New password must be at least 8 characters long"})
	}

	if newPassword != confirmPassword {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "New password and confirmation do not match"})
	}

	// Find the user in the database using ObjectID
	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Verify the old password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Old password is incorrect"})
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	// Update the password in the database
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"password": string(hashedPassword)}},
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to update password"})
	}

	return c.JSON(fiber.Map{"message": "Password updated successfully"})
}

func Auth(app *fiber.App) {
	app.Get("/auth/signup", limiter.New(rateLimitConfig), UserSignup)
	app.Get("/auth/login", limiter.New(rateLimitConfig), UserLogin)
	app.Post("/auth/change-password", limiter.New(rateLimitConfig), authMiddleware, ChangePassword)
	app.Post("/auth/logout", UserLogout)
	app.Get("/auth/@me", authMiddleware, CurrentUser)
}
