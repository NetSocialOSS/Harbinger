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
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	userId, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Set up a context with a timeout to avoid long-running operations
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Retrieve user details to send the goodbye email
	var user types.User
	err = usersCollection.FindOne(ctx, bson.M{"id": userId}).Decode(&user)
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
	count, err := usersCollection.CountDocuments(ctx, bson.M{"id": userId})
	if err != nil {
		http.Error(w, "Failed to check if user exists", http.StatusInternalServerError)
		return
	}
	if count == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Delete the user from the users collection
	_, err = usersCollection.DeleteOne(ctx, bson.M{"id": userId})
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Delete all posts authored by the user
	_, err = postsCollection.DeleteMany(ctx, bson.M{"author": userId})
	if err != nil {
		http.Error(w, "Failed to delete posts", http.StatusInternalServerError)
		return
	}

	// Delete all coteries owned by the user
	_, err = coteriesCollection.DeleteMany(ctx, bson.M{"owner": userId})
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

	action := r.URL.Query().Get("action")

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

	// Initialize response with user details
	response := map[string]interface{}{
		"username":       user.Username,
		"displayname":    user.DisplayName,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isBanned":       user.IsBanned,
		"isModerator":    user.IsModerator,
		"isPartner":      user.IsPartner,
		"bio":            user.Bio,
		"createdAt":      user.CreatedAt,
		"profilePicture": user.ProfilePicture,
		"profileBanner":  user.ProfileBanner,
		"followersCount": len(user.Followers),
		"followingCount": len(user.Following),
		"links":          user.Links,
	}

	// If the user is private, return minimal data
	if user.IsPrivate {
		response["message"] = "This account is private"
		json.NewEncoder(w).Encode(response)
		return
	}

	// Helper function to resolve user IDs to usernames
	userIDToUsername := make(map[string]string)
	getUsername := func(id string) (string, error) {
		if username, found := userIDToUsername[id]; found {
			return username, nil
		}
		var u types.User
		err := userCollection.FindOne(r.Context(), bson.M{"id": id}).Decode(&u)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return "Unknown User", nil
			}
			return "", err
		}
		userIDToUsername[id] = u.Username
		return u.Username, nil
	}

	// Helper function to process post data
	processPost := func(post types.Post, author types.User) (map[string]interface{}, error) {
		// Resolve usernames in hearts
		var hearts []string
		for _, heartID := range post.Hearts {
			username, err := getUsername(heartID)
			if err != nil {
				return nil, fmt.Errorf("error resolving heart usernames: %v", err)
			}
			hearts = append(hearts, username)
		}

		// Process poll data if present
		if post.Poll != nil {
			totalVotes := 0
			for i := range post.Poll {
				for j := range post.Poll[i].Options {
					optionVoteCount := len(post.Poll[i].Options[j].Votes)
					totalVotes += optionVoteCount

					post.Poll[i].Options[j].Votes = nil
					post.Poll[i].Options[j].VoteCount = optionVoteCount
				}
			}
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		// Construct post data
		return map[string]interface{}{
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
				"isModerator":    author.IsModerator,
			},
			"poll":          post.Poll,
			"image":         post.Image,
			"createdAt":     post.CreatedAt,
			"hearts":        hearts,
			"commentNumber": len(post.Comments),
		}, nil
	}

	// Handle "followers" or "following" actions
	if action == "followers" || action == "following" {
		var userIDs []string
		if action == "followers" {
			userIDs = user.Followers
		} else {
			userIDs = user.Following
		}

		var usernames []string
		for _, id := range userIDs {
			username, err := getUsername(id)
			if err != nil {
				http.Error(w, "Error resolving usernames", http.StatusInternalServerError)
				return
			}
			usernames = append(usernames, username)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			action: usernames,
		})
		return
	}

	// Handle "hearts" action
	if action == "hearts" {
		if user.IsPrivateHearts {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "This user has their hearted posts set as private!",
			})
			return
		}

		var heartedPosts []map[string]interface{}
		postCollection := db.Database("SocialFlux").Collection("posts")
		cursor, err := postCollection.Find(r.Context(), bson.M{"hearts": user.ID}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
		if err != nil {
			http.Error(w, "Failed to fetch hearted posts", http.StatusInternalServerError)
			return
		}
		defer cursor.Close(r.Context())

		for cursor.Next(r.Context()) {
			var post types.Post
			err := cursor.Decode(&post)
			if err != nil {
				http.Error(w, "Error decoding post data", http.StatusInternalServerError)
				return
			}

			// Skip non-indexable posts
			if !post.Indexing {
				continue
			}

			// Fetch author details
			var author types.User
			err = userCollection.FindOne(r.Context(), bson.M{"id": post.Author}).Decode(&author)
			if err != nil {
				http.Error(w, "Error fetching author data", http.StatusInternalServerError)
				return
			}

			postData, err := processPost(post, author)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			heartedPosts = append(heartedPosts, postData)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"posts": heartedPosts,
		})
		return
	}

	// Handle "posts" or default action
	if action == "" || action == "posts" {
		var posts []map[string]interface{}
		postCollection := db.Database("SocialFlux").Collection("posts")
		cursor, err := postCollection.Find(r.Context(), bson.M{"author": user.ID}, options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}}))
		if err != nil {
			http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
			return
		}
		defer cursor.Close(r.Context())

		for cursor.Next(r.Context()) {
			var post types.Post
			err := cursor.Decode(&post)
			if err != nil {
				http.Error(w, "Error decoding post data", http.StatusInternalServerError)
				return
			}

			// Skip non-indexable posts
			if !post.Indexing {
				continue
			}

			postData, err := processPost(post, user)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			posts = append(posts, postData)
		}

		response["posts"] = posts
	}

	// Final response
	json.NewEncoder(w).Encode(response)
}

func UpdateProfileSettings(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	userID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
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
	filter := bson.M{"id": userID}
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
	action := r.URL.Query().Get("action") // This could be either "follow" or "unfollow"

	userCollection := db.Database("SocialFlux").Collection("users")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	followerID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Find the user to be followed/unfollowed
	var userToBeUpdated bson.M
	err = userCollection.FindOne(r.Context(), bson.M{"username": username}).Decode(&userToBeUpdated)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding user", http.StatusInternalServerError)
		return
	}

	// Find the follower user
	var followerUser bson.M
	err = userCollection.FindOne(r.Context(), bson.M{"id": followerID}).Decode(&followerUser)
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
	if userToBeUpdated["id"] == followerUser["id"] {
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
		_, err := userCollection.UpdateOne(r.Context(), bson.M{"id": followerID}, bson.M{"$set": bson.M{"following": bson.A{}}})
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
		followerUserUpdate = bson.M{"$addToSet": bson.M{"following": userToBeUpdated["id"]}}
	} else if action == "unfollow" {
		// Remove follower's user ID from the user's followers list
		followedUserUpdate = bson.M{"$pull": bson.M{"followers": followerID}}
		// Remove followed user's ID from the follower's following list
		followerUserUpdate = bson.M{"$pull": bson.M{"following": userToBeUpdated["id"]}}
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
	followerUserFilter := bson.M{"id": followerID}
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

	// Retrieve the userId from header
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId header is required", http.StatusBadRequest)
		return
	}
	userID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	// Set up a context with a timeout to avoid long-running operations
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Find the user by ID and retrieve the current value of privacy settings
	var user bson.M
	err = usersCollection.FindOne(ctx, bson.M{"id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
		return
	}

	// Retrieve the action parameter from the query string
	action := r.Header.Get("X-action")
	if action == "" {
		http.Error(w, "action parameter is required", http.StatusBadRequest)
		return
	}

	// Prepare the update document
	update := bson.M{}

	// Define possible actions and handle them
	switch action {
	case "togglePrivateHearts":
		// Check if 'isPrivateHearts' exists and is a bool, if not, set it to false
		isPrivateHearts, ok := user["isPrivateHearts"].(bool)
		if !ok {
			// If it doesn't exist or is not a bool, set it to false
			update["$set"] = bson.M{"isPrivateHearts": false}
			isPrivateHearts = false
		}

		// Toggle the value
		update["$set"] = bson.M{"isPrivateHearts": !isPrivateHearts}

	case "togglePrivateAccount":
		// Check if 'isPrivate' exists and is a bool, if not, set it to false
		isPrivate, ok := user["isPrivate"].(bool)
		if !ok {
			// If it doesn't exist or is not a bool, set it to false
			update["$set"] = bson.M{"isPrivate": false}
			isPrivate = false
		}

		// Toggle the value
		update["$set"] = bson.M{"isPrivate": !isPrivate}

	default:
		http.Error(w, "Invalid action parameter", http.StatusBadRequest)
		return
	}

	// Perform the update if any changes were made
	if len(update) > 0 {
		_, err = usersCollection.UpdateOne(ctx, bson.M{"id": userID}, update, options.Update().SetUpsert(false))
		if err != nil {
			http.Error(w, "Failed to update privacy settings", http.StatusInternalServerError)
			return
		}
	}

	// Respond with the updated privacy settings
	w.WriteHeader(http.StatusOK)
	response := map[string]interface{}{
		"message": "Privacy setting updated successfully",
	}

	// Include the updated settings in the response
	if action == "togglePrivateHearts" {
		// Return the updated isPrivateHearts value (opposite of what it was)
		response["isPrivateHeartsNow"] = !user["isPrivateHearts"].(bool)
	}

	if action == "togglePrivateAccount" {
		// Return the updated isPrivate value (opposite of what it was)
		response["isPrivateNow"] = !user["isPrivate"].(bool)
	}

	json.NewEncoder(w).Encode(response)
}

func User(r *chi.Mux) {
	r.Post("/user/account/delete", (middlewares.DiscordErrorReport(http.HandlerFunc(deleteAccount)).ServeHTTP))
	r.Get("/user/{username}", (middlewares.DiscordErrorReport(http.HandlerFunc(GetUserByName)).ServeHTTP))
	r.Post("/profile/settings", (middlewares.DiscordErrorReport(http.HandlerFunc(UpdateProfileSettings)).ServeHTTP))
	r.Post("/user/FollowOrUnfollowUser", (middlewares.DiscordErrorReport(http.HandlerFunc(FollowOrUnfollowUser)).ServeHTTP))
	r.Post("/user/settings/privacy", (middlewares.DiscordErrorReport(http.HandlerFunc(TogglePrivacy)).ServeHTTP))
}
