package nist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"log/slog"

	"xploit4us-ingestor/internal/config"
	"xploit4us-ingestor/internal/models"
)

const (
	NISTAPIURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

// Client handles communication with the NIST NVD API
type Client struct {
	baseURL        string
	resultsPerPage int
	maxRetries     int
	retryDelay     time.Duration
	requestDelay   time.Duration
	httpClient     *http.Client
	logger         *slog.Logger
}

// NewClient creates a new NIST API client
func NewClient(cfg config.NISTConfig, logger *slog.Logger) *Client {
	return &Client{
		baseURL:        NISTAPIURL,
		resultsPerPage: 2000, // Constant - max allowed by NIST API
		maxRetries:     cfg.MaxRetries,
		retryDelay:     cfg.RetryDelay,
		requestDelay:   cfg.RequestDelay,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		logger: logger,
	}
}

// FetchVulnerabilities fetches vulnerabilities from the NIST API
// Returns the response and whether there are more pages to fetch
func (c *Client) FetchVulnerabilities(ctx context.Context, startIndex int) (*models.NISTResponse, bool, error) {
	return c.FetchVulnerabilitiesWithFilters(ctx, startIndex, "", "")
}

// FetchVulnerabilitiesWithFilters fetches vulnerabilities with date filters
// lastModStart and lastModEnd should be in ISO-8601 format
// Both dates must be provided together (NIST API requirement)
func (c *Client) FetchVulnerabilitiesWithFilters(
	ctx context.Context,
	startIndex int,
	lastModStart string,
	lastModEnd string,
) (*models.NISTResponse, bool, error) {

	params := url.Values{}
	params.Set("resultsPerPage", strconv.Itoa(c.resultsPerPage))
	params.Set("startIndex", strconv.Itoa(startIndex))

	// NIST requires both start and end dates together
	if lastModStart != "" && lastModEnd != "" {
		params.Set("lastModStartDate", lastModStart)
		params.Set("lastModEndDate", lastModEnd)
	}

	url := fmt.Sprintf("%s?%s", c.baseURL, params.Encode())

	c.logger.Debug("Fetching from NIST API",
		slog.String("url", url),
		slog.Int("startIndex", startIndex),
	)

	var resp *models.NISTResponse
	var err error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		resp, err = c.doRequest(ctx, url)
		if err == nil {
			break
		}

		if attempt < c.maxRetries {
			c.logger.Warn("NIST API request failed, retrying",
				slog.Int("attempt", attempt+1),
				slog.Int("maxRetries", c.maxRetries),
				slog.String("error", err.Error()),
			)
			time.Sleep(c.retryDelay)
		}
	}

	if err != nil {
		return nil, false, fmt.Errorf("failed after %d retries: %w", c.maxRetries, err)
	}

	// Check if there are more pages
	// hasMore is true if we got a full page and there are more results
	hasMore := len(resp.Vulnerabilities) == c.resultsPerPage && 
		(startIndex + len(resp.Vulnerabilities)) < resp.TotalResults

	c.logger.Info("Fetched vulnerabilities from NIST",
		slog.Int("startIndex", startIndex),
		slog.Int("resultsPerPage", resp.ResultsPerPage),
		slog.Int("totalResults", resp.TotalResults),
		slog.Bool("hasMore", hasMore),
	)

	return resp, hasMore, nil
}

func (c *Client) doRequest(ctx context.Context, url string) (*models.NISTResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "xploit4us-ingestor/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var nistResp models.NISTResponse
	if err := json.Unmarshal(body, &nistResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &nistResp, nil
}

// FetchAllVulnerabilities fetches all vulnerabilities from the API
// It handles pagination automatically and calls the callback for each batch
func (c *Client) FetchAllVulnerabilities(
	ctx context.Context,
	lastModStart string,
	lastModEnd string,
	callback func(vulns []models.NISTVulnerability, rawJSONs []json.RawMessage) error,
) error {

	startIndex := 0
	totalFetched := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		resp, hasMore, err := c.FetchVulnerabilitiesWithFilters(
			ctx, startIndex, lastModStart, lastModEnd,
		)
		if err != nil {
			return err
		}

		// Extract raw JSON for each vulnerability
		rawJSONs := make([]json.RawMessage, len(resp.Vulnerabilities))
		for i, vuln := range resp.Vulnerabilities {
			rawJSON, err := json.Marshal(vuln)
			if err != nil {
				return fmt.Errorf("failed to marshal vulnerability %d: %w", i, err)
			}
			rawJSONs[i] = rawJSON
		}

		if err := callback(resp.Vulnerabilities, rawJSONs); err != nil {
			return fmt.Errorf("callback failed: %w", err)
		}

		totalFetched += len(resp.Vulnerabilities)

		if !hasMore {
			break
		}

		// Increment by actual results count, not requested count
		startIndex += len(resp.Vulnerabilities)

		// Add delay between requests to avoid rate limiting
		if c.requestDelay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(c.requestDelay):
			}
		}
	}

	c.logger.Info("Finished fetching all vulnerabilities",
		slog.Int("totalFetched", totalFetched),
	)

	return nil
}
