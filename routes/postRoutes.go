package routes

import (
	"net/http"
	"netsocial/middlewares"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

func RateLimit(limit int, burst time.Duration) func(http.Handler) http.Handler {
	// Create a rate limiter
	limiter := rate.NewLimiter(rate.Every(burst/time.Duration(limit)), limit)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter.Allow() {
				next.ServeHTTP(w, r)
			} else {
				// Rate limit exceeded, return a custom message
				w.WriteHeader(http.StatusTooManyRequests) // Set status code to 429
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("Woah! Slow down bucko! You're being rate limited!"))
			}
		})
	}
}

func PostRoutes(r chi.Router) {
	r.With(RateLimit(5, 5*time.Minute)).Post("/comment/add", (middlewares.DiscordErrorReport(http.HandlerFunc(AddComment)).ServeHTTP))
	r.Get("/posts/@all", GetAllPosts)
	r.Get("/posts/{id}", GetPostById)
	r.With(RateLimit(5, 5*time.Minute)).Post("/post/action", (middlewares.DiscordErrorReport(http.HandlerFunc(PostActions)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Delete("/post/delete", (middlewares.DiscordErrorReport(http.HandlerFunc(DeletePost)).ServeHTTP))
	r.With(RateLimit(5, 5*time.Minute)).Post("/post/add", (middlewares.DiscordErrorReport(http.HandlerFunc(AddPost)).ServeHTTP))
}
