package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func ManageBadge(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	username := r.Header.Get("X-username")
	action := r.Header.Get("X-action")
	badge := r.Header.Get("X-badge")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner
	usersCollection := db.Database("SocialFlux").Collection("users")
	modFilter := bson.M{"id": modID}
	var modUser types.User
	err = usersCollection.FindOne(context.Background(), modFilter).Decode(&modUser)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !modUser.IsOwner && !modUser.IsModerator && !modUser.IsDeveloper {
		http.Error(w, `{"error": "Permission denied. Only owners, moderators, or developers can manage badges."}`, http.StatusForbidden)
		return
	}

	// Find the user by username
	userFilter := bson.M{"username": username}
	var user types.User
	err = usersCollection.FindOne(context.Background(), userFilter).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Update the user's badge based on action
	update := bson.M{}
	switch action {
	case "add":
		update = handleBadgeUpdate(user, badge, true)
	case "remove":
		update = handleBadgeUpdate(user, badge, false)
	default:
		http.Error(w, `{"error": "Invalid action"}`, http.StatusBadRequest)
		return
	}

	// Apply the update to the user
	_, err = usersCollection.UpdateOne(context.Background(), userFilter, bson.M{"$set": update})
	if err != nil {
		http.Error(w, `{"error": "Failed to update user badges"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Badge %s successfully %sed for user %s", badge, action, username),
	})
}

func handleBadgeUpdate(_ types.User, badge string, add bool) bson.M {
	switch badge {
	case "dev":
		return bson.M{"isDeveloper": add}
	case "verified":
		return bson.M{"isVerified": add}
	case "partner":
		return bson.M{"isPartner": add}
	case "owner":
		return bson.M{"isOwner": add}
	case "moderator":
		return bson.M{"isModerator": add}
	default:
		return bson.M{}
	}
}

func DeletePostAdmin(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	postID := r.Header.Get("X-postId")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner
	usersCollection := db.Database("SocialFlux").Collection("users")
	modFilter := bson.M{"id": modID}
	var modUser types.User
	err = usersCollection.FindOne(context.Background(), modFilter).Decode(&modUser)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !modUser.IsOwner && !modUser.IsModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can delete posts."}`, http.StatusForbidden)
		return
	}

	// Delete the post from the database
	postsCollection := db.Database("SocialFlux").Collection("posts")
	deleteFilter := bson.M{"id": postID}
	result, err := postsCollection.DeleteOne(context.Background(), deleteFilter)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete post"}`, http.StatusInternalServerError)
		return
	}
	if result.DeletedCount == 0 {
		http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Post with ID %s successfully deleted", postID),
	})
}

func DeleteCoterieAdmin(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieName := r.Header.Get("X-name")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner
	usersCollection := db.Database("SocialFlux").Collection("users")
	modFilter := bson.M{"id": modID}
	var modUser types.User
	err = usersCollection.FindOne(context.Background(), modFilter).Decode(&modUser)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !modUser.IsOwner && !modUser.IsModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can delete coteries."}`, http.StatusForbidden)
		return
	}

	// Delete the coterie from the database
	coteriesCollection := db.Database("SocialFlux").Collection("coterie")
	deleteFilter := bson.M{"name": coterieName}
	result, err := coteriesCollection.DeleteOne(context.Background(), deleteFilter)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete coterie"}`, http.StatusInternalServerError)
		return
	}
	if result.DeletedCount == 0 {
		http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Coterie with name %s successfully deleted", coterieName),
	})
}

func ManageUser(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	username := r.Header.Get("X-username")
	action := r.Header.Get("X-action")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner
	usersCollection := db.Database("SocialFlux").Collection("users")
	modFilter := bson.M{"id": modID}
	var modUser types.User
	err = usersCollection.FindOne(context.Background(), modFilter).Decode(&modUser)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !modUser.IsOwner && !modUser.IsModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can manage users."}`, http.StatusForbidden)
		return
	}

	// Find the user by username
	userFilter := bson.M{"username": username}
	var user types.User
	err = usersCollection.FindOne(context.Background(), userFilter).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Update the user's ban status based on action
	update := bson.M{}
	switch action {
	case "ban":
		update = bson.M{"isBanned": true}
	case "unban":
		update = bson.M{"isBanned": false}
	default:
		http.Error(w, `{"error": "Invalid action"}`, http.StatusBadRequest)
		return
	}

	// Apply the update to the user
	_, err = usersCollection.UpdateOne(context.Background(), userFilter, bson.M{"$set": update})
	if err != nil {
		http.Error(w, `{"error": "Failed to update user status"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("User %s successfully %sed", username, action),
	})
}

func Admin(r chi.Router) {
	r.With(RateLimit(5, 10*time.Minute)).Post("/admin/manage/badge", (middlewares.DiscordErrorReport(http.HandlerFunc(ManageBadge)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Post("/admin/manage/user", (middlewares.DiscordErrorReport(http.HandlerFunc(ManageUser)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Delete("/admin/manage/post", (middlewares.DiscordErrorReport(http.HandlerFunc(DeletePostAdmin)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Delete("/admin/manage/coterie", (middlewares.DiscordErrorReport(http.HandlerFunc(DeleteCoterieAdmin)).ServeHTTP))
}
