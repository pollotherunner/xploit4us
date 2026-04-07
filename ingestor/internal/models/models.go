package models

import (
	"time"
)

// ============================================================================
// Vulnerability Models
// ============================================================================

// Vulnerability represents a normalized vulnerability record
type Vulnerability struct {
	CVEID            string
	SourceName       string
	Description      string
	PublishedDate    time.Time
	LastModifiedDate time.Time
	VulnStatus       string
	CVSSVersion      string
	BaseScore        float32
	BaseSeverity     string
	VectorString     string
}

// NIST API Response structures (for parsing only, not stored raw)
type NISTResponse struct {
	ResultsPerPage  int                 `json:"resultsPerPage"`
	StartIndex      int                 `json:"startIndex"`
	TotalResults    int                 `json:"totalResults"`
	Format          string              `json:"format"`
	Version         string              `json:"version"`
	Timestamp       string              `json:"timestamp"`
	Vulnerabilities []NISTVulnerability `json:"vulnerabilities"`
}

type NISTVulnerability struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID               string        `json:"id"`
	SourceIdentifier string        `json:"sourceIdentifier"`
	Published        string        `json:"published"`
	LastModified     string        `json:"lastModified"`
	VulnStatus       string        `json:"vulnStatus"`
	CVEMetrics       CVEMetrics    `json:"metrics,omitempty"`
	Descriptions     []Description `json:"descriptions"`
	References       []Reference   `json:"references"`
}

type CVEMetrics struct {
	CVSSMetricV2 []CVSSMetricV2 `json:"cvssMetricV2,omitempty"`
	CVSSMetricV3 []CVSSMetricV3 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV4 []CVSSMetricV4 `json:"cvssMetricV40,omitempty"`
}

type CVSSMetricV2 struct {
	Source       string     `json:"source"`
	Type         string     `json:"type"`
	CVSSData     CVSSV2Data `json:"cvssData"`
	BaseSeverity string     `json:"baseSeverity"`
}

type CVSSMetricV3 struct {
	Source       string     `json:"source"`
	Type         string     `json:"type"`
	CVSSData     CVSSV3Data `json:"cvssData"`
	BaseSeverity string     `json:"baseSeverity"`
}

type CVSSMetricV4 struct {
	Source       string     `json:"source"`
	Type         string     `json:"type"`
	CVSSData     CVSSV4Data `json:"cvssData"`
	BaseSeverity string     `json:"baseSeverity"`
}

type CVSSV2Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
}

type CVSSV3Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float32 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
	ExploitabilityScore   float32 `json:"exploitabilityScore"`
	ImpactScore           float32 `json:"impactScore"`
}

type CVSSV4Data struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float32 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags,omitempty"`
}

// ============================================================================
// Exploit Models
// ============================================================================

// Exploit represents a normalized exploit record from multiple sources
type Exploit struct {
	ID             int64
	SourceName     string     // "ExploitDB" or "GitHub"
	Title          string
	Author         string
	Type           string
	Platform       string
	DatePublished  *time.Time
	IsVerified     bool
	PocURL         string     // Direct PoC URL (exploit-db link or GitHub repo URL)
	GithubStars    int
}

// GitHubRepo represents a repository from PoC-in-GitHub API
type GitHubRepo struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	FullName      string    `json:"full_name"`
	HTMLURL       string    `json:"html_url"`
	Description   string    `json:"description"`
	Fork          bool      `json:"fork"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	StargazersCount int     `json:"stargazers_count"`
	ForksCount    int       `json:"forks_count"`
	Owner         struct {
		Login    string `json:"login"`
		ID       int64  `json:"id"`
		AvatarURL string `json:"avatar_url"`
		HTMLURL  string `json:"html_url"`
	} `json:"owner"`
}
