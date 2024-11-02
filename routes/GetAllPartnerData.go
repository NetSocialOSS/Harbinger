package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"netsocial/types"

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
