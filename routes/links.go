package routes

import (
	"net/http"
	"net/url"
	"netsocial/types"
	"strings"

	"github.com/gocolly/colly/v2"
	"github.com/gofiber/fiber/v2"
)

// ExtractLinkPreview handles the extraction of link previews
func ExtractLinkPreview(c *fiber.Ctx) error {
	urlParam := c.Query("url")

	// Validate the URL parameter
	if urlParam == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "URL parameter is required"})
	}

	// Parse the URL to ensure it's valid
	parsedURL, err := url.Parse(urlParam)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid URL"})
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
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch the URL"})
	}

	// Set the domain
	linkPreview.Domain = parsedURL.Host

	return c.JSON(linkPreview)
}
