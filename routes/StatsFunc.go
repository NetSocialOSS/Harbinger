package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"

	"github.com/go-chi/chi/v5"
)

// getCount retrieves the count of records from the specified table
func getCount(w http.ResponseWriter, r *http.Request, tableName string, fieldName string) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	query := "SELECT COUNT(*) FROM \"" + tableName + "\""
	var total int
	if err := db.QueryRowContext(context.Background(), query).Scan(&total); err != nil {
		http.Error(w, "Error counting records", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{fieldName: total})
}

// RegistergedUserNum retrieves the count of registered users
func RegistergedUserNum(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "users", "total_registered_user")
}

// TotalPartnersCount retrieves the count of partners
func TotalPartnersCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "partner", "total_partners")
}

// TotalPostsCount retrieves the count of posts
func TotalPostsCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "post", "total_posts")
}

// TotalCoterieCount retrieves the count of coteries
func TotalCoterieCount(w http.ResponseWriter, r *http.Request) {
	getCount(w, r, "coterie", "total_coteries")
}

// Stats registers the statistics routes with the Chi router
func Stats(r chi.Router) {
	r.Get("/stats/posts/@all", (middlewares.DiscordErrorReport(http.HandlerFunc(TotalPostsCount)).ServeHTTP))
	r.Get("/stats/coterie/@all", (middlewares.DiscordErrorReport(http.HandlerFunc(TotalCoterieCount)).ServeHTTP))
	r.Get("/stats/partners/@all", (middlewares.DiscordErrorReport(http.HandlerFunc(TotalPartnersCount)).ServeHTTP))
	r.Get("/stats/users/@all", (middlewares.DiscordErrorReport(http.HandlerFunc(RegistergedUserNum)).ServeHTTP))
}
