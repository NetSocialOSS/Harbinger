package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// GetAllPartner retrieves all partners from the database
func GetAllPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available - partners", http.StatusInternalServerError)
		return
	}

	partnersCollection := db.Database("SocialFlux").Collection("partners")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cursor, err := partnersCollection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var partners []types.Partner
	if err := cursor.All(ctx, &partners); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	// Encode partners to JSON and write to the response
	if err := json.NewEncoder(w).Encode(partners); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func AddNewPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	encryptedid := r.Header.Get("X-userId")
	Title := r.URL.Query().Get("title")
	text := r.URL.Query().Get("description")
	Link := r.URL.Query().Get("link")
	Logo := r.URL.Query().Get("logo")
	Banner := r.URL.Query().Get("banner")

	UserID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Since UserID is now a UUID string, we don't need ObjectIDFromHex
	_, err = uuid.Parse(UserID)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	userCollection := db.Database("SocialFlux").Collection("users")
	var user types.User

	// Query the users collection using UUID string
	err = userCollection.FindOne(context.Background(), bson.M{"id": UserID}).Decode(&user)
	if err == mongo.ErrNoDocuments || !(user.IsDeveloper || user.IsOwner) {
		http.Error(w, "User not authorized to add partners", http.StatusForbidden)
		return
	} else if err != nil {
		logAndReturnError(w, "Failed to fetch user data", err)
		return
	}

	blogCollection := db.Database("SocialFlux").Collection("partners")
	newPost := types.Partner{
		ID:     uuid.New().String(),
		Title:  Title,
		Text:   text,
		Link:   Link,
		Banner: Banner,
		Logo:   Logo,
	}

	_, err = blogCollection.InsertOne(context.Background(), newPost)
	if err != nil {
		logAndReturnError(w, "Failed to insert blog post", err)
		return
	}

	// Respond with success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(newPost); err != nil {
		logAndReturnError(w, "Failed to encode response", err)
		return
	}
}

func Partner(r chi.Router) {
	r.Get("/partners/@all", GetAllPartner)
	r.Post("/partner/new", AddNewPartner)
}
