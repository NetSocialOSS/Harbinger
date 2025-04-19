package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4/pgxpool"
)

// GetAllPartner retrieves all partners from the DB
func GetAllPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Database connection not available - partners", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(context.Background(), "SELECT id, banner, logo, title, text, link FROM partner")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var partners []types.Partner
	for rows.Next() {
		var partner types.Partner
		err := rows.Scan(&partner.ID, &partner.Banner, &partner.Logo, &partner.Title, &partner.Text, &partner.Link)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		partners = append(partners, partner)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(partners); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func AddNewPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error":"Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	Title := r.URL.Query().Get("name")
	text := r.URL.Query().Get("description")
	Link := r.URL.Query().Get("link")
	Logo := r.URL.Query().Get("logo")
	Banner := r.URL.Query().Get("banner")
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}

	decryptedUserID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var isDeveloper, isOwner bool
	err = db.QueryRow(context.Background(), `SELECT isdeveloper, isowner FROM users WHERE id = $1`, decryptedUserID).Scan(&isDeveloper, &isOwner)
	if err != nil {
		http.Error(w, `{"error":"User not found or not authorized"}`, http.StatusForbidden)
		return
	}

	if !(isDeveloper || isOwner) {
		http.Error(w, `{"error":"User not authorized to add partners"}`, http.StatusForbidden)
		return
	}

	newPartner := types.Partner{
		Title:  Title,
		Text:   text,
		Link:   Link,
		Banner: Banner,
		Logo:   Logo,
	}

	_, err = db.Exec(context.Background(), `
		INSERT INTO partner (title, text, link, banner, logo) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		newPartner.Title, newPartner.Text, newPartner.Link, newPartner.Banner, newPartner.Logo,
	)
	if err != nil {
		http.Error(w, `{"error":"Failed to insert partner"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	response := map[string]interface{}{
		"success": true,
		"message": "Partner added successfully",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error":"Failed to encode success response"}`, http.StatusInternalServerError)
	}
}

func Partner(r chi.Router) {
	r.With(RateLimit(5, 5*time.Minute)).Get("/partners/@all", GetAllPartner)
	r.With(RateLimit(5, 5*time.Minute)).Post("/partner/new", AddNewPartner)
}
