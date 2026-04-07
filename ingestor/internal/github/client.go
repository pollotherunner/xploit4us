package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"log/slog"

	"xploit4us-ingestor/internal/database"
	"xploit4us-ingestor/internal/models"
)

const (
	// PoC-in-GitHub repository URL
	PoCGitHubRepoURL = "https://github.com/nomi-sec/PoC-in-GitHub.git"
	// PoC-in-GitHub raw base URL for fallback
	PoCGitHubRawBaseURL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/refs/heads/master"
)

// CVEPattern matches CVE IDs
var CVEPattern = regexp.MustCompile(`CVE-\d{4}-\d+`)

// Client handles fetching PoCs from GitHub
type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	cacheDir   string
}

// NewClient creates a new GitHub PoC client
func NewClient(logger *slog.Logger) *Client {
	cacheDir := os.Getenv("GITHUB_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = "/tmp/poc-in-github"
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		logger:   logger,
		cacheDir: cacheDir,
	}
}

// FetchAndProcess clones PoC-in-GitHub and processes all CVEs
func (c *Client) FetchAndProcess(ctx context.Context, db *database.Database) error {
	c.logger.Info("Starting GitHub PoC ingestion")

	// Clone or update repository
	repoPath, err := c.cloneOrUpdateRepo(ctx)
	if err != nil {
		return fmt.Errorf("failed to clone/update repo: %w", err)
	}

	c.logger.Info("Repository ready", slog.String("path", repoPath))

	totalRepos := 0
	totalLinks := 0
	cvesWithPocs := make(map[string]int)

	// Walk through all year directories
	entries, err := os.ReadDir(repoPath)
	if err != nil {
		return fmt.Errorf("failed to read repo dir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		year := entry.Name()
		if !strings.HasPrefix(year, "20") {
			continue
		}

		yearPath := filepath.Join(repoPath, year)
		cveCount, err := c.processYearDirectory(ctx, db, yearPath, year, &totalRepos, &totalLinks, cvesWithPocs)
		if err != nil {
			c.logger.Warn("Failed to process year",
				slog.String("year", year),
				slog.String("error", err.Error()),
			)
			continue
		}

		c.logger.Debug("Processed year",
			slog.String("year", year),
			slog.Int("cves", cveCount),
		)
	}

	c.logger.Info("GitHub PoC ingestion completed",
		slog.Int("total_repos", totalRepos),
		slog.Int("total_links", totalLinks),
		slog.Int("unique_cves_with_pocs", len(cvesWithPocs)),
	)

	return nil
}

// cloneOrUpdateRepo clones the repo if not exists, or pulls updates
func (c *Client) cloneOrUpdateRepo(ctx context.Context) (string, error) {
	repoPath := c.cacheDir

	// Check if already exists
	if _, err := os.Stat(repoPath); err == nil {
		// Pull updates
		c.logger.Info("Updating existing repository")
		cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "pull", "--quiet")
		if err := cmd.Run(); err != nil {
			c.logger.Warn("Failed to pull updates, continuing with existing repo", slog.String("error", err.Error()))
		}
		return repoPath, nil
	}

	// Clone repository
	c.logger.Info("Cloning PoC-in-GitHub repository", slog.String("url", PoCGitHubRepoURL))
	
	// Remove if exists (clean clone)
	os.RemoveAll(repoPath)
	os.MkdirAll(repoPath, 0755)

	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--quiet", PoCGitHubRepoURL, repoPath)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to clone: %w", err)
	}

	c.logger.Info("Repository cloned successfully")
	return repoPath, nil
}

// processYearDirectory processes all CVE JSON files in a year directory
func (c *Client) processYearDirectory(ctx context.Context, db *database.Database, yearPath, year string, totalRepos, totalLinks *int, cvesWithPocs map[string]int) (int, error) {
	cveCount := 0

	entries, err := os.ReadDir(yearPath)
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		// Extract CVE from filename (e.g., CVE-2024-1234.json)
		cveID := strings.TrimSuffix(entry.Name(), ".json")
		if !CVEPattern.MatchString(cveID) {
			continue
		}

		filePath := filepath.Join(yearPath, entry.Name())
		repos, err := c.parseCVEFile(filePath)
		if err != nil {
			c.logger.Debug("Failed to parse CVE file",
				slog.String("file", entry.Name()),
				slog.String("error", err.Error()),
			)
			continue
		}

		// Process each repo for this CVE
		for _, repo := range repos {
			exploit := c.githubRepoToExploit(repo, cveID)

			exploitID, err := db.UpsertExploit(ctx, exploit)
			if err != nil {
				c.logger.Warn("Failed to upsert exploit",
					slog.String("repo", repo.FullName),
					slog.String("error", err.Error()),
				)
				continue
			}

			*totalRepos++

			if err := db.LinkExploitToCVE(ctx, exploitID, cveID); err != nil {
				c.logger.Debug("Failed to link exploit to CVE",
					slog.Int64("exploit_id", exploitID),
					slog.String("cve", cveID),
					slog.String("error", err.Error()),
				)
			} else {
				*totalLinks++
				cvesWithPocs[cveID]++
			}
		}

		cveCount++

		if *totalRepos%1000 == 0 {
			c.logger.Info("Progress",
				slog.Int("repos_processed", *totalRepos),
				slog.Int("links_created", *totalLinks),
				slog.Int("unique_cves", len(cvesWithPocs)),
			)
		}
	}

	return cveCount, nil
}

// parseCVEFile parses a CVE JSON file and returns list of repos
func (c *Client) parseCVEFile(filePath string) ([]models.GitHubRepo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var repos []models.GitHubRepo
	if err := json.Unmarshal(data, &repos); err != nil {
		return nil, err
	}

	return repos, nil
}

// githubRepoToExploit converts a GitHubRepo to our Exploit model
func (c *Client) githubRepoToExploit(repo models.GitHubRepo, cveID string) *models.Exploit {
	return &models.Exploit{
		SourceName:    "GitHub",
		Title:         repo.Description,
		Author:        repo.Owner.Login,
		Type:          "github",
		Platform:      "multiple",
		DatePublished: &repo.CreatedAt,
		IsVerified:    false,
		PocURL:        repo.HTMLURL,
		GithubStars:   repo.StargazersCount,
	}
}
