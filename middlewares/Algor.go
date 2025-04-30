package middlewares

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"netsocial/types"
)

// FetchRunningModel fetches the currently running model from Ollama
func FetchRunningModel() (string, error) {
	resp, err := http.Get(configuration.Algor.OllamaURL + "/api/ps")
	if err != nil {
		return "", errors.New("[Algor] Failed to fetch running models: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("[Algor] Ollama responded with status: " + http.StatusText(resp.StatusCode))
	}

	var psResponse types.ModelResponse
	if err := json.NewDecoder(resp.Body).Decode(&psResponse); err != nil {
		return "", errors.New("[Algor] Failed to parse JSON response: " + err.Error())
	}

	if len(psResponse.Models) == 0 {
		return "None", nil
	}

	return psResponse.Models[0].Model, nil
}

// FetchOllamaVersion fetches the version of Ollama
func FetchOllamaVersion() (string, error) {
	resp, err := http.Get(configuration.Algor.OllamaURL + "/api/version")
	if err != nil {
		return "", errors.New("[Algor] Failed to fetch Ollama version: " + err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("[Algor] Ollama responded with status: " + http.StatusText(resp.StatusCode))
	}

	var versionResponse struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&versionResponse); err != nil {
		return "", errors.New("[Algor] Failed to parse JSON response: " + err.Error())
	}
	return versionResponse.Version, nil
}

func Algor() {
	log.Println("[Algor] Loading Algor model...")

	// Fetch running model
	runningModel, err := FetchRunningModel()
	if err != nil {
		log.Println(err)
		runningModel = "Unknown"
	}

	// Fetch Ollama version
	ollamaVersion, err := FetchOllamaVersion()
	if err != nil {
		log.Println(err)
		ollamaVersion = "Unknown"
	}

	log.Printf("[Algor] Running model: %s, Ollama version: %s", runningModel, ollamaVersion)
}
