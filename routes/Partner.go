package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"netsocial/middlewares"
	"netsocial/types"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GetAllPartner retrieves all partners from the DB
func GetAllPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available - partners", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query("SELECT id, banner, logo, title, text, link FROM partner")
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

// AddNewPartner adds a new partner to the DB
func AddNewPartner(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
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
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	_, err = uuid.Parse(UserID)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusBadRequest)
		return
	}

	var user types.User
	err = db.QueryRow(`SELECT id, isDeveloper, isOwner FROM users WHERE id = $1`, UserID).Scan(&user.ID, &user.IsDeveloper, &user.IsOwner)
	if err != nil || !(user.IsDeveloper || user.IsOwner) {
		http.Error(w, "User not authorized to add partners", http.StatusForbidden)
		return
	}

	newPartner := types.Partner{
		ID:     uuid.New().String(),
		Title:  Title,
		Text:   text,
		Link:   Link,
		Banner: Banner,
		Logo:   Logo,
	}

	_, err = db.Exec(`
		INSERT INTO partner (id, title, text, link, banner, logo) 
		VALUES ($1, $2, $3, $4, $5, $6)`,
		newPartner.ID, newPartner.Title, newPartner.Text, newPartner.Link, newPartner.Banner, newPartner.Logo,
	)
	if err != nil {
		http.Error(w, "Failed to insert partner", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(newPartner); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func Partner(r chi.Router) {
	r.Get("/partners/@all", GetAllPartner)
	r.Post("/partner/new", AddNewPartner)
}
