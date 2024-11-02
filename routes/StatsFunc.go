package routes

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// getCount retrieves the count of documents from the specified collection
func getCount(w http.ResponseWriter, r *http.Request, collectionName string, fieldName string) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	collection := db.Database("SocialFlux").Collection(collectionName)

	countOptions := options.Count()
	total, err := collection.CountDocuments(context.Background(), bson.M{}, countOptions)
	if err != nil {
		http.Error(w, "Error counting documents", http.StatusInternalServerError)
		return
	}

	// Return the total count as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{fieldName: total})
}

// RegistergedUserNum retrieves the count of registered users
func RegistergedUserNum(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "users", "total_registered_user")
}

// TotalPartnersCount retrieves the count of partners
func TotalPartnersCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "partners", "total_partner")
}

// TotalPostsCount retrieves the count of posts
func TotalPostsCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "posts", "total_posts")
}

// TotalCoterieCount retrieves the count of coteries
func TotalCoterieCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "coterie", "total_coteries")
}

// Stats registers the statistics routes with the Chi router
func Stats(r chi.Router) {
	r.Get("/stats/posts/@all", TotalPostsCount)
	r.Get("/stats/coterie/@all", TotalCoterieCount)
	r.Get("/stats/partners/@all", TotalPartnersCount)
	r.Get("/stats/users/@all", RegistergedUserNum)
}
