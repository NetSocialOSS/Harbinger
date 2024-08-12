package routes

import (
	"context"
	"net/url"
	"netsocial/types"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/resend/resend-go/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func deleteAccount(c *fiber.Ctx) error {
	// Get the MongoDB client from Fiber's context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	// Get the users, posts, and coteries collections
	usersCollection := db.Database("SocialFlux").Collection("users")
	postsCollection := db.Database("SocialFlux").Collection("posts")
	coteriesCollection := db.Database("SocialFlux").Collection("coteries")

	// Retrieve the userId from query parameters
	userID := c.Query("userId")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "userId query parameter is required",
		})
	}

	// Convert the userID to a primitive.ObjectID
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid userID provided",
		})
	}

	// Set up a context with a timeout to avoid long-running operations
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Retrieve user details to send the goodbye email
	var user types.User
	err = usersCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve user details",
		})
	}

	// Send goodbye email
	err = sendGoodbyeEmail(user.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to send goodbye email",
		})
	}

	// Check if the user exists in the users collection
	count, err := usersCollection.CountDocuments(ctx, bson.M{"_id": objID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to check if user exists",
		})
	}
	if count == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Delete the user from the users collection
	_, err = usersCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	// Delete all posts authored by the user
	_, err = postsCollection.DeleteMany(ctx, bson.M{"author": objID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete posts",
		})
	}

	// Delete all coteries owned by the user
	_, err = coteriesCollection.DeleteMany(ctx, bson.M{"owner": objID})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete coteries",
		})
	}

	// Respond with a success message
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User, their posts, and coteries deleted successfully",
	})
}

func sendGoodbyeEmail(email string) error {
	apiKey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apiKey)
	params := &resend.SendEmailRequest{
		From:    "Netsocial <goodbye@netsocial.app>",
		To:      []string{email},
		Subject: "Goodbye from Netsocial",
		Text:    "We're sorry to see you go. If you change your mind, you can always come back and start anew journey. [Rejoin Netsocial](https://netsocial.app/signup).",
	}
	_, err := client.Emails.Send(params)
	return err
}

func GetUserByName(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	if username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Name parameter is required"})
	}

	var user types.User
	userCollection := db.Database("SocialFlux").Collection("users")
	result := userCollection.FindOne(context.Background(), bson.M{"username": username})
	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching user data"})
	}

	err := result.Decode(&user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error decoding user data"})
	}

	// Fetch posts made by the user without comments, sorted by createdAt in descending order
	var posts []types.Post
	postCollection := db.Database("SocialFlux").Collection("posts")
	cursor, err := postCollection.Find(context.TODO(), bson.M{"author": user.ID}, options.Find().SetSort(bson.D{{"createdAt", -1}}))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch posts"})
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	// Utility function to get username from ID
	getUsername := func(id primitive.ObjectID) (string, error) {
		if username, found := userIDToUsername[id]; found {
			return username, nil
		}
		var u types.User
		err := userCollection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&u)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return "Unknown User", nil
			}
			return "", err
		}
		userIDToUsername[id] = u.Username
		return u.Username, nil
	}

	for cursor.Next(context.TODO()) {
		var post types.Post
		err := cursor.Decode(&post)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error decoding posts data"})
		}

		// Replace user IDs in hearts with usernames
		for i, heart := range post.Hearts {
			heartID, err := primitive.ObjectIDFromHex(heart)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid heart ID"})
			}
			username, err := getUsername(heartID)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching heart user data"})
			}
			post.Hearts[i] = username
		}

		// Exclude comments from the post
		post.Comments = nil
		posts = append(posts, post)
	}

	// Convert followers and following from IDs to usernames
	var followersUsernames, followingUsernames []string

	for _, followerID := range user.Followers {
		followerObjectID, err := primitive.ObjectIDFromHex(followerID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid follower ID"})
		}
		username, err := getUsername(followerObjectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching follower user data"})
		}
		followersUsernames = append(followersUsernames, username)
	}

	for _, followingID := range user.Following {
		followingObjectID, err := primitive.ObjectIDFromHex(followingID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid following ID"})
		}
		username, err := getUsername(followingObjectID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching following user data"})
		}
		followingUsernames = append(followingUsernames, username)
	}

	return c.JSON(fiber.Map{
		"username":       user.Username,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isBanned":       user.IsBanned,
		"isPartner":      user.IsPartner,
		"displayname":    user.DisplayName,
		"bio":            user.Bio,
		"createdAt":      user.CreatedAt,
		"followersCount": len(user.Followers),
		"followingCount": len(user.Following),
		"followers":      followersUsernames,
		"following":      followingUsernames,
		"links":          user.Links,
		"posts":          posts,
	})
}

func UpdateProfileSettings(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	userID := c.Query("userId")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "userId query parameter is required",
		})
	}

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid userID provided",
		})
	}

	// Retrieve update parameters from both query and request body
	var updateParams types.UserSettingsUpdate

	// Helper function to decode URL-encoded values
	decodeIfNotEmpty := func(value string) string {
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			return value // Return original value if decoding fails
		}
		return decoded
	}

	// Parsing and decoding query parameters
	if displayName := c.Query("displayName"); displayName != "" {
		updateParams.DisplayName = decodeIfNotEmpty(displayName)
	}
	if bio := c.Query("bio"); bio != "" {
		updateParams.Bio = decodeIfNotEmpty(bio)
	}
	if profilePicture := c.Query("profilePicture"); profilePicture != "" {
		updateParams.ProfilePicture = decodeIfNotEmpty(profilePicture)
	}
	if profileBanner := c.Query("profileBanner"); profileBanner != "" {
		updateParams.ProfileBanner = decodeIfNotEmpty(profileBanner)
	}
	if links := c.Query("links"); links != "" {
		decodedLinks := decodeIfNotEmpty(links)
		updateParams.Links = strings.Split(decodedLinks, ",")
	}

	// Parsing request body parameters (if any)
	if err := c.BodyParser(&updateParams); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Error parsing request body",
		})
	}

	// Prepare update filter and update fields
	updateFields := bson.M{}
	if updateParams.DisplayName != "" {
		updateFields["displayName"] = updateParams.DisplayName
	}
	if updateParams.Bio != "" {
		updateFields["bio"] = updateParams.Bio
	}
	if updateParams.ProfilePicture != "" {
		updateFields["profilePicture"] = updateParams.ProfilePicture
	}
	if updateParams.ProfileBanner != "" {
		updateFields["profileBanner"] = updateParams.ProfileBanner
	}
	if len(updateParams.Links) > 0 {
		updateFields["links"] = updateParams.Links
	}

	// Perform update operation
	usersCollection := db.Database("SocialFlux").Collection("users")
	filter := bson.M{"_id": objID}

	update := bson.M{"$set": updateFields}

	// Use UpdateOne with Upsert option to prevent overriding existing fields with empty strings
	opts := options.Update().SetUpsert(true)
	_, err = usersCollection.UpdateOne(context.Background(), filter, update, opts)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user profile",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Profile settings updated successfully!",
	})
}

// FollowUser allows one user to follow another
func FollowUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	followerID := c.Params("followerID")

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be followed
	var userToBeFollowed bson.M
	err := userCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&userToBeFollowed)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding user"})
	}

	// Find the follower user
	var followerUser bson.M
	followerObjectID, err := primitive.ObjectIDFromHex(followerID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid follower ID"})
	}

	err = userCollection.FindOne(context.TODO(), bson.M{"_id": followerObjectID}).Decode(&followerUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Follower not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding follower"})
	}

	// Add follower's user ID to the user's followers list
	followedUserFilter := bson.M{"username": username}
	followedUserUpdate := bson.M{"$addToSet": bson.M{"followers": followerID}}
	_, err = userCollection.UpdateOne(context.TODO(), followedUserFilter, followedUserUpdate, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating followers list"})
	}

	// Add followed user's ID to the follower's following list
	followerUserFilter := bson.M{"_id": followerObjectID}
	followerUserUpdate := bson.M{"$addToSet": bson.M{"following": userToBeFollowed["_id"].(primitive.ObjectID).Hex()}}
	_, err = userCollection.UpdateOne(context.TODO(), followerUserFilter, followerUserUpdate, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating following list"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully followed user"})
}

func UnfollowUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Params("username")
	followerID := c.Params("followerID")

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be unfollowed
	var user bson.M
	err := userCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding user"})
	}

	// Remove follower's user ID from the user's followers list
	filter := bson.M{"username": username}
	update := bson.M{"$pull": bson.M{"followers": followerID}}
	_, err = userCollection.UpdateOne(context.TODO(), filter, update, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error updating followers list"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Successfully unfollowed user"})
}

func User(app *fiber.App) {
	app.Post("/user/account/delete", limiter.New(rateLimitConfig), deleteAccount)
	app.Get("/user/:username", GetUserByName)
	app.Post("/profile/settings", limiter.New(rateLimitConfig), UpdateProfileSettings)
	app.Post("/follow/:username/:followerID", limiter.New(rateLimitConfig), FollowUser)
	app.Post("/unfollow/:username/:followerID", limiter.New(rateLimitConfig), UnfollowUser)

}
