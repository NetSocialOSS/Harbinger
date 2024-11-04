package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"netsocial/middlewares"
	"netsocial/types"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/resend/resend-go/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	// Get the MongoDB client from the request context
	db := r.Context().Value("db").(*mongo.Client)

	// Get the users, posts, and coteries collections
	usersCollection := db.Database("SocialFlux").Collection("users")
	postsCollection := db.Database("SocialFlux").Collection("posts")
	coteriesCollection := db.Database("SocialFlux").Collection("coteries")

	// Retrieve the userId from query parameters
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	// Convert the userID to a primitive.ObjectID
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid userID provided", http.StatusBadRequest)
		return
	}

	// Set up a context with a timeout to avoid long-running operations
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Retrieve user details to send the goodbye email
	var user types.User
	err = usersCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
		return
	}

	// Send goodbye email
	err = sendGoodbyeEmail(user.Email)
	if err != nil {
		http.Error(w, "Failed to send goodbye email", http.StatusInternalServerError)
		return
	}

	// Check if the user exists in the users collection
	count, err := usersCollection.CountDocuments(ctx, bson.M{"_id": objID})
	if err != nil {
		http.Error(w, "Failed to check if user exists", http.StatusInternalServerError)
		return
	}
	if count == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Delete the user from the users collection
	_, err = usersCollection.DeleteOne(ctx, bson.M{"_id": objID})
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Delete all posts authored by the user
	_, err = postsCollection.DeleteMany(ctx, bson.M{"author": objID})
	if err != nil {
		http.Error(w, "Failed to delete posts", http.StatusInternalServerError)
		return
	}

	// Delete all coteries owned by the user
	_, err = coteriesCollection.DeleteMany(ctx, bson.M{"owner": objID})
	if err != nil {
		http.Error(w, "Failed to delete coteries", http.StatusInternalServerError)
		return
	}

	// Respond with a success message
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User, their posts, and coteries deleted successfully"})
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

func GetUserByName(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, "Name parameter is required", http.StatusBadRequest)
		return
	}

	var user types.User
	userCollection := db.Database("SocialFlux").Collection("users")
	result := userCollection.FindOne(r.Context(), bson.M{"username": username})
	if result.Err() != nil {
		if result.Err() == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	err := result.Decode(&user)
	if err != nil {
		http.Error(w, "Error decoding user data", http.StatusInternalServerError)
		return
	}

	// If the user is private, do not show their posts, followers, or following
	if user.IsPrivate {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username":       user.Username,
			"displayname":    user.DisplayName,
			"isVerified":     user.IsVerified,
			"isOrganisation": user.IsOrganisation,
			"isPrivate":      user.IsPrivate,
			"isDeveloper":    user.IsDeveloper,
			"isOwner":        user.IsOwner,
			"isBanned":       user.IsBanned,
			"isModerator":    user.IsModerator,
			"isPartner":      user.IsPartner,
			"bio":            user.Bio,
			"createdAt":      user.CreatedAt,
			"followersCount": len(user.Followers),
			"followingCount": len(user.Following),
			"links":          user.Links,
			"message":        "This account is private",
		})
		return
	}

	// Fetch posts made by the user without comments, sorted by createdAt in descending order
	var posts []map[string]interface{}
	postCollection := db.Database("SocialFlux").Collection("posts")
	cursor, err := postCollection.Find(r.Context(), bson.M{"author": user.ID}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
	if err != nil {
		http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
		return
	}

	// Create a map to store user IDs and their corresponding usernames
	userIDToUsername := make(map[primitive.ObjectID]string)

	// Utility function to get username from ID
	getUsername := func(id primitive.ObjectID) (string, error) {
		if username, found := userIDToUsername[id]; found {
			return username, nil
		}
		var u types.User
		err := userCollection.FindOne(r.Context(), bson.M{"_id": id}).Decode(&u)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return "Unknown User", nil
			}
			return "", err
		}
		userIDToUsername[id] = u.Username
		return u.Username, nil
	}

	for cursor.Next(r.Context()) {
		var post types.Post
		err := cursor.Decode(&post)
		if err != nil {
			http.Error(w, "Error decoding posts data", http.StatusInternalServerError)
			return
		}

		// Fetch author details
		var author types.User
		err = userCollection.FindOne(r.Context(), bson.M{"_id": post.Author}).Decode(&author)
		if err != nil {
			http.Error(w, "Error fetching author data", http.StatusInternalServerError)
			return
		}

		// Replace user IDs in hearts with usernames
		var hearts []string
		for _, heartIDHex := range post.Hearts {
			heartID, err := primitive.ObjectIDFromHex(heartIDHex)
			if err != nil {
				http.Error(w, "Invalid heart ID", http.StatusInternalServerError)
				return
			}
			username, err := getUsername(heartID)
			if err != nil {
				http.Error(w, "Error fetching heart user data", http.StatusInternalServerError)
				return
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

		// Get current time
		now := time.Now()

		// Check the scheduled time
		if !post.ScheduledFor.IsZero() {
			if post.ScheduledFor.After(now) {
				// Post is scheduled for the future, skip it
				continue
			}
			// If the scheduledFor is today or in the past, we continue to process the post
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
				"isModerator":    user.IsModerator,
			},
			"poll":          post.Poll,
			"image":         post.Image,
			"createdAt":     post.CreatedAt,
			"hearts":        hearts,
			"commentNumber": len(post.Comments),
		}
		if !post.ScheduledFor.IsZero() {
			postData["scheduledFor"] = post.ScheduledFor
		}
		posts = append(posts, postData)
	}

	// Convert followers and following from IDs to usernames
	var followersUsernames, followingUsernames []string

	for _, followerID := range user.Followers {
		followerObjectID, err := primitive.ObjectIDFromHex(followerID)
		if err != nil {
			http.Error(w, "Invalid follower ID", http.StatusInternalServerError)
			return
		}
		username, err := getUsername(followerObjectID)
		if err != nil {
			http.Error(w, "Error fetching follower user data", http.StatusInternalServerError)
			return
		}
		followersUsernames = append(followersUsernames, username)
	}

	for _, followingID := range user.Following {
		followingObjectID, err := primitive.ObjectIDFromHex(followingID)
		if err != nil {
			http.Error(w, "Invalid following ID", http.StatusInternalServerError)
			return
		}
		username, err := getUsername(followingObjectID)
		if err != nil {
			http.Error(w, "Error fetching following user data", http.StatusInternalServerError)
			return
		}
		followingUsernames = append(followingUsernames, username)
	}

	// Return full user data if the account is not private
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":       user.Username,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isBanned":       user.IsBanned,
		"isModerator":    user.IsModerator,
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

func UpdateProfileSettings(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid userID provided", http.StatusBadRequest)
		return
	}

	// Retrieve update parameters
	updateFields := bson.M{}

	// Helper function to decode and add fields to updateFields
	decodeAndAddField := func(param string, field string) {
		if value := r.URL.Query().Get(param); value != "" {
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
	if links := r.URL.Query().Get("links"); links != "" {
		decodedLinks, err := url.QueryUnescape(links)
		if err == nil {
			updateFields["links"] = strings.Split(decodedLinks, ",")
		}
	}

	// Handle IsOrganisation
	if isOrgQueryParam := r.URL.Query().Get("isOrganisation"); isOrgQueryParam != "" {
		if isOrg, err := strconv.ParseBool(isOrgQueryParam); err == nil {
			updateFields["isOrganisation"] = isOrg

		}
	}

	// Perform update operation
	usersCollection := db.Database("SocialFlux").Collection("users")
	filter := bson.M{"_id": objID}
	update := bson.M{"$set": updateFields}

	result, err := usersCollection.UpdateOne(r.Context(), filter, update)
	if err != nil {
		http.Error(w, "Failed to update user profile", http.StatusInternalServerError)
		return
	}

	if result.ModifiedCount == 0 {
		http.Error(w, "User not found or no changes made", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Profile settings updated successfully!",
		"updates": updateFields,
	})
}

func FollowOrUnfollowUser(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	username := r.URL.Query().Get("username")
	followerID := r.URL.Query().Get("userId")
	action := r.URL.Query().Get("action") // This could be either "follow" or "unfollow"

	userCollection := db.Database("SocialFlux").Collection("users")

	// Find the user to be followed/unfollowed
	var userToBeUpdated bson.M
	err := userCollection.FindOne(r.Context(), bson.M{"username": username}).Decode(&userToBeUpdated)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding user", http.StatusInternalServerError)
		return
	}

	// Find the follower user
	followerObjectID, err := primitive.ObjectIDFromHex(followerID)
	if err != nil {
		http.Error(w, "Invalid follower ID", http.StatusBadRequest)
		return
	}

	var followerUser bson.M
	err = userCollection.FindOne(r.Context(), bson.M{"_id": followerObjectID}).Decode(&followerUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Follower not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding follower", http.StatusInternalServerError)
		return
	}

	// Check if the follower user is banned
	if isBanned, ok := followerUser["isbanned"].(bool); ok && isBanned {
		http.Error(w, "Hey there, you are banned from using NetSocial's services.", http.StatusForbidden)
		return
	}

	// Check if the followerID is the same as the userToBeUpdated ID
	if userToBeUpdated["_id"] == followerUser["_id"] {
		http.Error(w, "My guy, you can't follow yourself! That's cheating!!", http.StatusBadRequest)
		return
	}

	// Initialize followers and following if they are nil
	if userToBeUpdated["followers"] == nil {
		_, err := userCollection.UpdateOne(r.Context(), bson.M{"username": username}, bson.M{"$set": bson.M{"followers": bson.A{}}})
		if err != nil {
			http.Error(w, "Failed to initialize followers list", http.StatusInternalServerError)
			return
		}
		userToBeUpdated["followers"] = bson.A{} // Update local variable to reflect change
	}
	if followerUser["following"] == nil {
		_, err := userCollection.UpdateOne(r.Context(), bson.M{"_id": followerObjectID}, bson.M{"$set": bson.M{"following": bson.A{}}})
		if err != nil {
			http.Error(w, "Failed to initialize following list", http.StatusInternalServerError)
			return
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
		http.Error(w, fmt.Sprintf("My guy, you are already following %s", username), http.StatusBadRequest)
		return
	}

	if action == "unfollow" && !isAlreadyFollowing {
		http.Error(w, fmt.Sprintf("My guy, you aren't even following %s", username), http.StatusBadRequest)
		return
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
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	// Update the user being followed/unfollowed
	followedUserFilter := bson.M{"username": username}
	_, err = userCollection.UpdateOne(r.Context(), followedUserFilter, followedUserUpdate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating followers list for user %s: %v", username, err), http.StatusInternalServerError)
		return
	}

	// Update the follower user
	followerUserFilter := bson.M{"_id": followerObjectID}
	_, err = userCollection.UpdateOne(r.Context(), followerUserFilter, followerUserUpdate)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating following list for user %s: %v", followerUser["username"], err), http.StatusInternalServerError)
		return
	}

	// Format the success message
	actionMessage := "followed"
	if action == "unfollow" {
		actionMessage = "unfollowed"
	}

	// Use fmt.Sprintf to format the success message correctly
	successMessage := fmt.Sprintf("Successfully %s %s", actionMessage, username)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": successMessage})
}

func TogglePrivacy(w http.ResponseWriter, r *http.Request) {
	// Get the MongoDB client from the request context
	db := r.Context().Value("db").(*mongo.Client)

	// Retrieve the userId from query parameters
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	// Convert the userID to a primitive.ObjectID
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid userID provided", http.StatusBadRequest)
		return
	}

	// Set up a context with a timeout to avoid long-running operations
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Find the user by ID and retrieve the current value of isPrivate
	var user bson.M
	err = usersCollection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
		return
	}

	// Toggle the isPrivate field
	isPrivate, ok := user["isPrivate"].(bool)
	if !ok {
		http.Error(w, "Error retrieving the isPrivate field", http.StatusInternalServerError)
		return
	}
	newPrivacyStatus := !isPrivate

	// Update the user's isPrivate field
	update := bson.M{
		"$set": bson.M{"isPrivate": newPrivacyStatus},
	}
	_, err = usersCollection.UpdateOne(ctx, bson.M{"_id": objID}, update, options.Update().SetUpsert(false))
	if err != nil {
		http.Error(w, "Failed to update privacy settings", http.StatusInternalServerError)
		return
	}

	// Respond with the new privacy status
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Privacy setting updated successfully",
		"isPrivateNow": newPrivacyStatus,
	})
}

func User(r *chi.Mux) {
	r.Post("/user/account/delete", (middlewares.DiscordErrorReport(http.HandlerFunc(deleteAccount)).ServeHTTP))
	r.Get("/user/{username}", (middlewares.DiscordErrorReport(http.HandlerFunc(GetUserByName)).ServeHTTP))
	r.Post("/profile/settings", (middlewares.DiscordErrorReport(http.HandlerFunc(UpdateProfileSettings)).ServeHTTP))
	r.Post("/user/FollowOrUnfollowUser", (middlewares.DiscordErrorReport(http.HandlerFunc(FollowOrUnfollowUser)).ServeHTTP))
	r.Post("/user/settings/privacy", (middlewares.DiscordErrorReport(http.HandlerFunc(TogglePrivacy)).ServeHTTP))
}
