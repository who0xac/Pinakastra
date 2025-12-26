package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client handles communication with Ollama API
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
	Model      string
}

// ChatRequest represents a chat request to Ollama
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Stream   bool      `json:"stream"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatResponse represents the response from Ollama
type ChatResponse struct {
	Model     string  `json:"model"`
	CreatedAt string  `json:"created_at"`
	Message   Message `json:"message"`
	Done      bool    `json:"done"`
}

// NewClient creates a new Ollama client
func NewClient(model string) *Client {
	return &Client{
		BaseURL: "http://localhost:11434",
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second, // 2 minutes timeout for AI responses
		},
		Model: model,
	}
}

// Chat sends a chat request to Ollama and returns the response
func (c *Client) Chat(ctx context.Context, prompt string) (string, error) {
	// Prepare request
	reqBody := ChatRequest{
		Model: c.Model,
		Messages: []Message{
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/chat", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var chatResp ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	return chatResp.Message.Content, nil
}

// IsAvailable checks if Ollama service is running
func (c *Client) IsAvailable(ctx context.Context) bool {
	url := fmt.Sprintf("%s/api/tags", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// CheckModel verifies if the specified model is available
func (c *Client) CheckModel(ctx context.Context) (bool, error) {
	url := fmt.Sprintf("%s/api/tags", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to connect to Ollama: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	// Parse response to check if model exists
	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	// Check if our model exists
	for _, model := range result.Models {
		if model.Name == c.Model || model.Name == c.Model+":latest" {
			return true, nil
		}
	}

	return false, nil
}
