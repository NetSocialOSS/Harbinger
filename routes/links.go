package routes

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"netsocial/types"

	"github.com/gocolly/colly/v2"
)

// ExtractLinkPreview handles the extraction of link previews
func ExtractLinkPreview(w http.ResponseWriter, r *http.Request) {
	urlParam := r.URL.Query().Get("url")

	// Validate the URL parameter
	if urlParam == "" {
		http.Error(w, `{"error": "URL parameter is required"}`, http.StatusBadRequest)
		return
	}

	// Parse the URL to ensure it's valid
	parsedURL, err := url.Parse(urlParam)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		http.Error(w, `{"error": "Invalid URL"}`, http.StatusBadRequest)
		return
	}

	// Create a new collector
	crawler := colly.NewCollector()

	// Initialize linkPreview
	linkPreview := types.LinkPreview{
		URL:    urlParam,
		Images: []string{},
	}

	// Extract title
	crawler.OnHTML("title", func(e *colly.HTMLElement) {
		linkPreview.Title = strings.TrimSpace(e.Text)
	})

	// Extract meta description
	crawler.OnHTML("meta[name='description']", func(e *colly.HTMLElement) {
		linkPreview.Description = strings.TrimSpace(e.Attr("content"))
	})

	// Extract Open Graph data
	crawler.OnHTML("meta[property='og:title']", func(e *colly.HTMLElement) {
		if linkPreview.Title == "" {
			linkPreview.Title = strings.TrimSpace(e.Attr("content"))
		}
	})

	crawler.OnHTML("meta[property='og:description']", func(e *colly.HTMLElement) {
		if linkPreview.Description == "" {
			linkPreview.Description = strings.TrimSpace(e.Attr("content"))
		}
	})

	crawler.OnHTML("meta[property='og:image']", func(e *colly.HTMLElement) {
		linkPreview.Images = append(linkPreview.Images, e.Attr("content"))
	})

	// Extract all <img> tags
	crawler.OnHTML("img[src]", func(e *colly.HTMLElement) {
		linkPreview.Images = append(linkPreview.Images, e.Attr("src"))
	})

	// Visit the URL
	err = crawler.Visit(urlParam)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch the URL"}`, http.StatusInternalServerError)
		return
	}

	// Set the domain
	linkPreview.Domain = parsedURL.Host

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")
	// Encode linkPreview to JSON and write to the response
	if err := json.NewEncoder(w).Encode(linkPreview); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}
}
