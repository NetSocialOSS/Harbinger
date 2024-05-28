package routes

import (
	"math/rand"
	"net/http"
	"socialflux/types"
	"time"

	"github.com/gofiber/fiber/v2"
)

var randomDescriptions = map[string][]string{
	"Online": []string{
		"Working Fine Chief!",
		"All systems go!",
		"Smooth sailing!",
		"Looks like everything is up today!",
	},
	"Degraded Performance": []string{
		"Oh no! Looks like we are having some minor issues which might affect performance of our sites.",
		"We're experiencing some hiccups, but we're on it!",
		"Performance is a bit shaky, but we're working to stabilize it.",
	},
	"Down": []string{
		"It's Down Chief! Maybe check back later?",
		"We're experiencing technical difficulties. Hang tight!",
		"Currently offline, but we're troubleshooting.",
	},
}

func getStatus(url string) (string, error) {
	client := http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "Down", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "Online", nil
	} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return "Degraded Performance", nil
	} else {
		return "Down", nil
	}
}

func getRandomDescription(status string) string {
	descriptions := randomDescriptions[status]
	if len(descriptions) == 0 {
		return ""
	}
	return descriptions[rand.Intn(len(descriptions))]
}

func GetStatusHandler(c *fiber.Ctx) error {
	statusData := []types.ServerStatus{
		{Name: "Production Site", URL: "https://netsocial.app"},
		{Name: "Beta Site", URL: "https://netsocial.app"},
		{Name: "API", URL: "https://api.netsocial.app"},
		{Name: "CDN", URL: "https://cdn.netsocial.app"},
	}

	for i := range statusData {
		if statusData[i].URL != "" {
			status, err := getStatus(statusData[i].URL)
			if err != nil {
				statusData[i].Status = "Down"
			} else {
				statusData[i].Status = status
			}
		} else {
			statusData[i].Status = "Down"
		}

		// Assign random descriptions based on status
		statusData[i].Description = getRandomDescription(statusData[i].Status)
	}

	return c.JSON(statusData)
}
