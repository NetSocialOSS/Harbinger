package routes

import (
	"context"
	"fmt"
	"net/url"
	"netsocial/types"
	"os"
	"strconv"
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

	// If the user is private, do not show their posts, followers, or following
	if user.IsPrivate {
		return c.JSON(fiber.Map{
			"username":       user.Username,
			"displayname":    user.DisplayName,
			"isVerified":     user.IsVerified,
			"isOrganisation": user.IsOrganisation,
			"isPrivate":      user.IsPrivate,
			"isDeveloper":    user.IsDeveloper,
			"isOwner":        user.IsOwner,
			"isBanned":       user.IsBanned,
			"isPartner":      user.IsPartner,
			"bio":            user.Bio,
			"createdAt":      user.CreatedAt,
			"followersCount": len(user.Followers),
			"followingCount": len(user.Following),
			"links":          user.Links,
			"message":        "This account is private",
		})
	}

	// Fetch posts made by the user without comments, sorted by createdAt in descending order
	var posts []map[string]interface{}
	postCollection := db.Database("SocialFlux").Collection("posts")
	cursor, err := postCollection.Find(context.TODO(), bson.M{"author": user.ID}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
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

		// Fetch author details
		var author types.User
		err = userCollection.FindOne(context.Background(), bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching author data"})
		}

		// Replace user IDs in hearts with usernames
		var hearts []string
		for _, heartIDHex := range post.Hearts {
			heartID, err := primitive.ObjectIDFromHex(heartIDHex)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid heart ID"})
			}
			username, err := getUsername(heartID)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching heart user data"})
			}
			hearts = append(hearts, username)
		}

		// Calculate total votes for polls if applicable
		if post.Poll != nil {
			totalVotes := 0
			for i := range post.Poll {
				for j := range post.Poll[i].Options {
					optionVoteCount := len(post.Poll[i].Options[j].Votes)
					totalVotes += optionVoteCount

					// Clear votes from the response but set vote count
					post.Poll[i].Options[j].Votes = nil
					post.Poll[i].Options[j].VoteCount = optionVoteCount
				}
			}
			// Set total votes for the first poll in the list
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		// Construct the post response data
		postData := map[string]interface{}{
			"_id":     post.ID,
			"title":   post.Title,
			"content": post.Content,
			"authorDetails": map[string]interface{}{
				"username":       author.Username,
				"isVerified":     author.IsVerified,
				"isOrganisation": author.IsOrganisation,
				"profileBanner":  author.ProfileBanner,
				"profilePicture": author.ProfilePicture,
				"isDeveloper":    author.IsDeveloper,
				"isPartner":      author.IsPartner,
				"isOwner":        author.IsOwner,
			},
			"poll":          post.Poll,
			"image":         post.Image,
			"createdAt":     post.CreatedAt,
			"hearts":        hearts,
			"commentNumber": len(post.Comments),
		}
		posts = append(posts, postData)
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

	// Return full user data if the account is not private
	return c.JSON(fiber.Map{
		"username":       user.Username,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isBanned":       user.IsBanned,
		"isPartner":      user.IsPartner,
		"displayname":    user.DisplayName,
		"profilePicture": user.ProfilePicture,
		"profileBanner":  user.ProfileBanner,
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

	// Retrieve update parameters
	updateFields := bson.M{}

	// Helper function to decode and add fields to updateFields
	decodeAndAddField := func(param string, field string) {
		if value := c.Query(param); value != "" {
			decoded, err := url.QueryUnescape(value)
			if err == nil {
				updateFields[field] = decoded
			}
		}
	}

	decodeAndAddField("displayName", "displayName")
	decodeAndAddField("bio", "bio")
	decodeAndAddField("profilePicture", "profilePicture")
	decodeAndAddField("profileBanner", "profileBanner")

	// Handle links
	if links := c.Query("links"); links != "" {
		decodedLinks, err := url.QueryUnescape(links)
		if err == nil {
			updateFields["links"] = strings.Split(decodedLinks, ",")
		}
	}

	// Handle IsOrganisation
	if isOrgQueryParam := c.Query("isOrganisation"); isOrgQueryParam != "" {
		if isOrg, err := strconv.ParseBool(isOrgQueryParam); err == nil {
			updateFields["isOrganisation"] = isOrg
		}
	}

	// Perform update operation
	usersCollection := db.Database("SocialFlux").Collection("users")
	filter := bson.M{"_id": objID}
	update := bson.M{"$set": updateFields}

	result, err := usersCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user profile",
		})
	}

	if result.ModifiedCount == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found or no changes made",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Profile settings updated successfully!",
		"updates": updateFields,
	})
}

// Follow or Unfollow user
func FollowOrUnfollowUser(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Database connection not available"})
	}

	username := c.Query("username")
	followerID := c.Query("userId")
	action := c.Query("action") // This could be either "follow" or "unfollow"

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be followed/unfollowed
	var userToBeUpdated bson.M
	err := userCollection.FindOne(context.TODO(), bson.M{"username": username}).Decode(&userToBeUpdated)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding user"})
	}

	// Find the follower user
	followerObjectID, err := primitive.ObjectIDFromHex(followerID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid follower ID"})
	}

	var followerUser bson.M
	err = userCollection.FindOne(context.TODO(), bson.M{"_id": followerObjectID}).Decode(&followerUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Follower not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error finding follower"})
	}

	// Check if the follower user is banned
	if isBanned, ok := followerUser["isbanned"].(bool); ok && isBanned {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Hey there, you are banned from using NetSocial's services.",
		})
	}

	// Check if the followerID is the same as the userToBeUpdated ID
	if userToBeUpdated["_id"] == followerUser["_id"] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "My guy, you can't follow yourself! That's cheating!!"})
	}

	// Initialize followers and following if they are nil
	if userToBeUpdated["followers"] == nil {
		_, err := userCollection.UpdateOne(context.TODO(), bson.M{"username": username}, bson.M{"$set": bson.M{"followers": bson.A{}}})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to initialize followers list"})
		}
		userToBeUpdated["followers"] = bson.A{} // Update local variable to reflect change
	}
	if followerUser["following"] == nil {
		_, err := userCollection.UpdateOne(context.TODO(), bson.M{"_id": followerObjectID}, bson.M{"$set": bson.M{"following": bson.A{}}})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to initialize following list"})
		}
		followerUser["following"] = bson.A{} // Update local variable to reflect change
	}

	// Check if the follower is already following the user
	followers := userToBeUpdated["followers"].(bson.A)
	isAlreadyFollowing := false
	for _, f := range followers {
		if f == followerID {
			isAlreadyFollowing = true
			break
		}
	}

	if action == "follow" && isAlreadyFollowing {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("My guy, you are already following %s", username)})
	}

	if action == "unfollow" && !isAlreadyFollowing {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": fmt.Sprintf("My guy, you aren't even following %s", username)})
	}

	// Determine the update operation based on the action
	var followedUserUpdate bson.M
	var followerUserUpdate bson.M

	if action == "follow" {
		// Add follower's user ID to the user's followers list
		followedUserUpdate = bson.M{"$addToSet": bson.M{"followers": followerID}}
		// Add followed user's ID to the follower's following list
		followerUserUpdate = bson.M{"$addToSet": bson.M{"following": userToBeUpdated["_id"].(primitive.ObjectID).Hex()}}
	} else if action == "unfollow" {
		// Remove follower's user ID from the user's followers list
		followedUserUpdate = bson.M{"$pull": bson.M{"followers": followerID}}
		// Remove followed user's ID from the follower's following list
		followerUserUpdate = bson.M{"$pull": bson.M{"following": userToBeUpdated["_id"].(primitive.ObjectID).Hex()}}
	} else {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid action"})
	}

	// Update the user being followed/unfollowed
	followedUserFilter := bson.M{"username": username}
	_, err = userCollection.UpdateOne(context.TODO(), followedUserFilter, followedUserUpdate)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Error updating followers list for user %s: %v", username, err)})
	}

	// Update the follower user
	followerUserFilter := bson.M{"_id": followerObjectID}
	_, err = userCollection.UpdateOne(context.TODO(), followerUserFilter, followerUserUpdate)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Error updating following list for user %s: %v", followerUser["username"], err)})
	}

	// Format the success message
	actionMessage := "followed"
	if action == "unfollow" {
		actionMessage = "unfollowed"
	}

	// Use fmt.Sprintf to format the success message correctly
	successMessage := fmt.Sprintf("Successfully %s %s", actionMessage, username)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": successMessage})
}

// TogglePrivacy allows a user to toggle the privacy of their profile (isPrivate field)
func TogglePrivacy(c *fiber.Ctx) error {
	// Get the MongoDB client from Fiber's context
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

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

	// Get the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Find the user by ID and retrieve the current value of isPrivate
	var user bson.M
	err = usersCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "User not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve user details",
		})
	}

	// Toggle the isPrivate field
	isPrivate, ok := user["isPrivate"].(bool)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error retrieving the isPrivate field",
		})
	}
	newPrivacyStatus := !isPrivate

	// Update the user's isPrivate field
	update := bson.M{
		"$set": bson.M{"isPrivate": newPrivacyStatus},
	}
	_, err = usersCollection.UpdateOne(ctx, bson.M{"_id": objID}, update, options.Update().SetUpsert(false))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update privacy settings",
		})
	}

	// Respond with the new privacy status
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message":      "Privacy setting updated successfully",
		"isPrivateNow": newPrivacyStatus,
	})
}

func User(app *fiber.App) {
	app.Post("/user/account/delete", limiter.New(rateLimitConfig), deleteAccount)
	app.Get("/user/:username", GetUserByName)
	app.Post("/profile/settings", limiter.New(rateLimitConfig), UpdateProfileSettings)
	app.Post("/user/FollowOrUnfollowUser", limiter.New(rateLimitConfig), FollowOrUnfollowUser)
	app.Post("/user/settings/privacy", limiter.New(rateLimitConfig), TogglePrivacy)
}
