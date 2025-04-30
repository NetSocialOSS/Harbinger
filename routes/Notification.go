package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v4/pgxpool"
)

func GetAllNotifications(w http.ResponseWriter, r *http.Request) {
	encryptedUserID := r.Header.Get("X-userID")
	if encryptedUserID == "" {
		http.Error(w, `{"error": "userId query parameter is required"}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt user ID"}`, http.StatusBadRequest)
		return
	}

	dbPool, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	rows, err := dbPool.Query(r.Context(),
		"SELECT id, type, content, link, isread, createdat FROM notifications WHERE userid = $1 ORDER BY createdat DESC",
		userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error fetching notifications: %v"}`, err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notifications []map[string]interface{}
	for rows.Next() {
		var notif types.Notification
		err := rows.Scan(&notif.ID, &notif.Type, &notif.Content, &notif.Link, &notif.IsRead, &notif.CreatedAt)
		if err != nil {
			http.Error(w, `{"error": "Error scanning notification"}`, http.StatusInternalServerError)
			return
		}

		notificationMap := map[string]interface{}{
			"id":        notif.ID,
			"type":      notif.Type,
			"content":   notif.Content,
			"link":      notif.Link,
			"isread":    notif.IsRead,
			"createdat": notif.CreatedAt,
		}
		notifications = append(notifications, notificationMap)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}

func DeleteAllNotifications(w http.ResponseWriter, r *http.Request) {
	encryptedUserID := r.Header.Get("X-userID")
	if encryptedUserID == "" {
		http.Error(w, `{"error": "userId query parameter is required"}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt user ID"}`, http.StatusBadRequest)
		return
	}

	dbPool, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	_, err = dbPool.Exec(r.Context(), "DELETE FROM notifications WHERE userid = $1", userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error deleting notifications: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "All notifications deleted successfully"})
}

func DeleteNotification(w http.ResponseWriter, r *http.Request) {
	encryptedUserID := r.Header.Get("X-userID")
	if encryptedUserID == "" {
		http.Error(w, `{"error": "userId query parameter is required"}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt user ID"}`, http.StatusBadRequest)
		return
	}

	notificationID := chi.URLParam(r, "id")
	if notificationID == "" {
		http.Error(w, `{"error": "Notification ID is required"}`, http.StatusBadRequest)
		return
	}

	dbPool, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	result, err := dbPool.Exec(r.Context(),
		"DELETE FROM notifications WHERE id = $1 AND userid = $2",
		notificationID, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error deleting notification: %v"}`, err), http.StatusInternalServerError)
		return
	}

	if rowsAffected := result.RowsAffected(); rowsAffected == 0 {
		http.Error(w, `{"error": "Notification not found or access denied"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Notification deleted successfully"})
}

func MarkAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	encryptedUserID := r.Header.Get("X-userID")
	if encryptedUserID == "" {
		http.Error(w, `{"error": "userId query parameter is required"}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt user ID"}`, http.StatusBadRequest)
		return
	}

	dbPool, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	_, err = dbPool.Exec(r.Context(), "UPDATE notifications SET isread = TRUE WHERE userid = $1", userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error marking notifications as read: %v"}`, err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "All notifications marked as read successfully"})
}

func MarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	encryptedUserID := r.Header.Get("X-userID")
	if encryptedUserID == "" {
		http.Error(w, `{"error": "userId query parameter is required"}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt user ID"}`, http.StatusBadRequest)
		return
	}

	notificationID := chi.URLParam(r, "id")
	if notificationID == "" {
		http.Error(w, `{"error": "Notification ID is required"}`, http.StatusBadRequest)
		return
	}

	dbPool, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	result, err := dbPool.Exec(r.Context(),
		"UPDATE notifications SET isread = TRUE WHERE id = $1 AND userid = $2",
		notificationID, userID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Error marking notification as read: %v"}`, err), http.StatusInternalServerError)
		return
	}

	if rowsAffected := result.RowsAffected(); rowsAffected == 0 {
		http.Error(w, `{"error": "Notification not found or access denied"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Notification marked as read successfully"})
}

func Notification(r *chi.Mux) {
	r.Get("/notification/@all", GetAllNotifications)
	r.With(RateLimit(5, 5*time.Minute)).Delete("/notification/delete/@all", DeleteAllNotifications)
	r.With(RateLimit(5, 5*time.Minute)).Delete("/notification/delete/{id}", DeleteNotification)
	r.Put("/notification/mark-read/@all", MarkAllNotificationsRead)
	r.Put("/notification/mark-read/{id}", MarkNotificationRead)
}
