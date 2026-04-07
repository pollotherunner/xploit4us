package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"xploit4us-ingestor/internal/models"
)

// Database wraps the pgxpool for vulnerability operations
type Database struct {
	pool *pgxpool.Pool
}

// New creates a new database connection
func New(ctx context.Context, dsn string) (*Database, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Database{pool: pool}, nil
}

// Close closes the database connection
func (db *Database) Close() {
	db.pool.Close()
}

// InitSchema creates the table and indexes if they don't exist
func (db *Database) InitSchema(ctx context.Context) error {
	// Create tables
	schema := `
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			cve_id VARCHAR(25) PRIMARY KEY,
			source_name VARCHAR(50) NOT NULL,
			description TEXT NOT NULL,
			published_date TIMESTAMP,
			last_modified_date TIMESTAMP,
			vuln_status VARCHAR(50),
			cvss_version VARCHAR(10),
			base_score NUMERIC(3,1),
			base_severity VARCHAR(20),
			vector_string TEXT,
			db_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS exploits (
			id SERIAL PRIMARY KEY,
			source_name VARCHAR(50) NOT NULL,
			title TEXT NOT NULL,
			author TEXT,
			type VARCHAR(50),
			platform VARCHAR(100),
			date_published DATE,
			is_verified BOOLEAN DEFAULT FALSE,
			poc_url TEXT NOT NULL UNIQUE,
			github_stars INTEGER DEFAULT 0,
			db_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS vulnerability_exploits (
			cve_id VARCHAR(25) NOT NULL,
			exploit_id INTEGER NOT NULL,
			linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (cve_id, exploit_id)
		);
	`

	_, err := db.pool.Exec(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Add unique constraint to poc_url if it doesn't exist (for existing tables)
	_, _ = db.pool.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT 1 FROM pg_constraint 
				WHERE conname = 'exploits_poc_url_key'
			) THEN
				ALTER TABLE exploits ADD CONSTRAINT exploits_poc_url_key UNIQUE (poc_url);
			END IF;
		END $$;
	`)

	// Create indexes separately to avoid issues with existing tables
	indexes := `
		-- Vulnerabilities indexes
		CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source_name);
		CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(base_severity);
		CREATE INDEX IF NOT EXISTS idx_vuln_cvss_score ON vulnerabilities(base_score);
		CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_date);
		CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vulnerabilities(last_modified_date);
		CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(vuln_status);

		-- Exploits indexes
		CREATE INDEX IF NOT EXISTS idx_exploit_source ON exploits(source_name);
		CREATE INDEX IF NOT EXISTS idx_exploit_platform ON exploits(platform);
		CREATE INDEX IF NOT EXISTS idx_exploit_type ON exploits(type);
		CREATE INDEX IF NOT EXISTS idx_exploit_date ON exploits(date_published);
		CREATE INDEX IF NOT EXISTS idx_exploit_verified ON exploits(is_verified);
		CREATE INDEX IF NOT EXISTS idx_exploit_poc_url ON exploits(poc_url);

		-- Vulnerability-Exploit link indexes
		CREATE INDEX IF NOT EXISTS idx_vuln_exploit_cve ON vulnerability_exploits(cve_id);
		CREATE INDEX IF NOT EXISTS idx_vuln_exploit_exploit ON vulnerability_exploits(exploit_id);
		CREATE INDEX IF NOT EXISTS idx_vuln_exploit_cve_exploit ON vulnerability_exploits(cve_id, exploit_id);
	`

	_, err = db.pool.Exec(ctx, indexes)
	if err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// UpsertVulnerabilitiesBatch inserts or updates vulnerabilities in batch.
// If forceUpdate is true, all fields are overwritten regardless of date.
// If forceUpdate is false, only newer records (by last_modified_date) are updated.
func (db *Database) UpsertVulnerabilitiesBatch(ctx context.Context, vulns []*models.Vulnerability, forceUpdate bool) (int, error) {
	batch := &pgx.Batch{}

	var query string
	if forceUpdate {
		query = `
			INSERT INTO vulnerabilities (
				cve_id, source_name, description, published_date, last_modified_date,
				vuln_status, cvss_version, base_score, base_severity, vector_string, db_updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP
			)
			ON CONFLICT (cve_id) DO UPDATE SET
				source_name = EXCLUDED.source_name,
				description = EXCLUDED.description,
				published_date = EXCLUDED.published_date,
				last_modified_date = EXCLUDED.last_modified_date,
				vuln_status = EXCLUDED.vuln_status,
				cvss_version = EXCLUDED.cvss_version,
				base_score = EXCLUDED.base_score,
				base_severity = EXCLUDED.base_severity,
				vector_string = EXCLUDED.vector_string,
				db_updated_at = CURRENT_TIMESTAMP
		`
	} else {
		query = `
			INSERT INTO vulnerabilities (
				cve_id, source_name, description, published_date, last_modified_date,
				vuln_status, cvss_version, base_score, base_severity, vector_string, db_updated_at
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP
			)
			ON CONFLICT (cve_id) DO UPDATE SET
				source_name = EXCLUDED.source_name,
				description = EXCLUDED.description,
				published_date = EXCLUDED.published_date,
				last_modified_date = EXCLUDED.last_modified_date,
				vuln_status = EXCLUDED.vuln_status,
				cvss_version = EXCLUDED.cvss_version,
				base_score = EXCLUDED.base_score,
				base_severity = EXCLUDED.base_severity,
				vector_string = EXCLUDED.vector_string,
				db_updated_at = CURRENT_TIMESTAMP
			WHERE vulnerabilities.last_modified_date < EXCLUDED.last_modified_date
		`
	}

	for _, vuln := range vulns {
		batch.Queue(query,
			vuln.CVEID,
			vuln.SourceName,
			vuln.Description,
			vuln.PublishedDate,
			vuln.LastModifiedDate,
			vuln.VulnStatus,
			vuln.CVSSVersion,
			vuln.BaseScore,
			vuln.BaseSeverity,
			vuln.VectorString,
		)
	}

	results := db.pool.SendBatch(ctx, batch)
	defer results.Close()

	upserted := 0
	for i := 0; i < len(vulns); i++ {
		cmdTag, err := results.Exec()
		if err != nil {
			return upserted, fmt.Errorf("batch item %d failed: %w", i, err)
		}
		upserted += int(cmdTag.RowsAffected())
	}

	return upserted, nil
}

// GetLastModifiedDate returns the most recent last_modified_date in the database
func (db *Database) GetLastModifiedDate(ctx context.Context) (*time.Time, error) {
	query := `SELECT MAX(last_modified_date) FROM vulnerabilities WHERE last_modified_date IS NOT NULL AND last_modified_date > '1970-01-01'`
	
	var maxTime *time.Time
	err := db.pool.QueryRow(ctx, query).Scan(&maxTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get last modified date: %w", err)
	}

	return maxTime, nil
}

// GetSyncMetadata returns metadata about the last sync
func (db *Database) GetSyncMetadata(ctx context.Context) (map[string]string, error) {
	query := `
		CREATE TABLE IF NOT EXISTS sync_metadata (
			key VARCHAR(255) PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`
	_, err := db.pool.Exec(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to create sync_metadata table: %w", err)
	}

	query = `SELECT key, value FROM sync_metadata`
	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query sync_metadata: %w", err)
	}
	defer rows.Close()

	metadata := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan metadata: %w", err)
		}
		metadata[key] = value
	}

	return metadata, nil
}

// UpdateSyncMetadata updates or inserts a metadata key-value pair
func (db *Database) UpdateSyncMetadata(ctx context.Context, key, value string) error {
	query := `
		INSERT INTO sync_metadata (key, value, updated_at) 
		VALUES ($1, $2, CURRENT_TIMESTAMP)
		ON CONFLICT (key) DO UPDATE SET 
			value = EXCLUDED.value,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := db.pool.Exec(ctx, query, key, value)
	return err
}

// GetFullSyncStartDate returns the date when the last full sync started
func (db *Database) GetFullSyncStartDate(ctx context.Context) (*time.Time, error) {
	metadata, err := db.GetSyncMetadata(ctx)
	if err != nil {
		return nil, err
	}

	if lastSyncStart, ok := metadata["last_full_sync_start"]; ok {
		t, err := time.Parse("2006-01-02T15:04:05.000", lastSyncStart)
		if err == nil {
			return &t, nil
		}
	}

	return nil, nil
}

// MarkFullSyncStarted records that a full sync has started
func (db *Database) MarkFullSyncStarted(ctx context.Context) error {
	now := time.Now().Format("2006-01-02T15:04:05.000")
	return db.UpdateSyncMetadata(ctx, "last_full_sync_start", now)
}

// MarkFullSyncCompleted records that a full sync has completed
func (db *Database) MarkFullSyncCompleted(ctx context.Context) error {
	now := time.Now().Format("2006-01-02T15:04:05.000")
	return db.UpdateSyncMetadata(ctx, "last_sync_completed", now)
}

// HasCompletedFullSync returns true if a full sync has been completed
func (db *Database) HasCompletedFullSync(ctx context.Context) (bool, error) {
	metadata, err := db.GetSyncMetadata(ctx)
	if err != nil {
		return false, err
	}

	_, has := metadata["last_full_sync_start"]
	return has, nil
}

// GetVulnerabilityCount returns total count of vulnerabilities
func (db *Database) GetVulnerabilityCount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM vulnerabilities`
	
	var count int64
	err := db.pool.QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get vulnerability count: %w", err)
	}

	return count, nil
}

// ParseNISTVulnerability converts a NIST vulnerability to our normalized model
func ParseNISTVulnerability(nistVuln models.NISTVulnerability) *models.Vulnerability {
	cve := nistVuln.CVE

	vuln := &models.Vulnerability{
		CVEID:      cve.ID,
		SourceName: "NIST",
		VulnStatus: cve.VulnStatus,
	}

	// Extract first English description
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			vuln.Description = desc.Value
			break
		}
	}
	// Fallback to any description if no English found
	if vuln.Description == "" && len(cve.Descriptions) > 0 {
		vuln.Description = cve.Descriptions[0].Value
	}

	// Parse published date - NIST uses ISO 8601 format
	if t, err := time.Parse("2006-01-02T15:04:05.000", cve.Published); err == nil {
		vuln.PublishedDate = t
	} else if t, err := time.Parse(time.RFC3339, cve.Published); err == nil {
		vuln.PublishedDate = t
	}

	// Parse last modified date - NIST uses ISO 8601 format
	if t, err := time.Parse("2006-01-02T15:04:05.000", cve.LastModified); err == nil {
		vuln.LastModifiedDate = t
	} else if t, err := time.Parse(time.RFC3339, cve.LastModified); err == nil {
		vuln.LastModifiedDate = t
	}

	// Extract CVSS metrics (priority: V4 > V3 > V2).
	// Skip versions with base score 0.0 (placeholder/unavailable).
	// Always take the baseSeverity directly from the NIST API response.
	extractCVSS(vuln, cve.CVEMetrics)

	return vuln
}

// extractCVSS picks the best available CVSS metric, preferring the most recent
// version with a non-zero base score.
func extractCVSS(v *models.Vulnerability, metrics models.CVEMetrics) {
	type cvss struct {
		version string
		score   float32
		vector  string
	}

	// Check each CVSS version in priority order (V4 > V3 > V2)
	candidates := []func() *cvss{
		func() *cvss {
			if len(metrics.CVSSMetricV4) == 0 {
				return nil
			}
			m := metrics.CVSSMetricV4[0]
			return &cvss{
				version: m.CVSSData.Version,
				score:   m.CVSSData.BaseScore,
				vector:  m.CVSSData.VectorString,
			}
		},
		func() *cvss {
			if len(metrics.CVSSMetricV3) == 0 {
				return nil
			}
			m := metrics.CVSSMetricV3[0]
			return &cvss{
				version: m.CVSSData.Version,
				score:   m.CVSSData.BaseScore,
				vector:  m.CVSSData.VectorString,
			}
		},
		func() *cvss {
			if len(metrics.CVSSMetricV2) == 0 {
				return nil
			}
			m := metrics.CVSSMetricV2[0]
			return &cvss{
				version: m.CVSSData.Version,
				score:   m.CVSSData.BaseScore,
				vector:  m.CVSSData.VectorString,
			}
		},
	}

	for _, fn := range candidates {
		c := fn()
		if c == nil {
			continue
		}
		// If score is 0.0, skip to next available version
		if c.score == 0.0 {
			continue
		}
		// Take the first non-zero score (highest priority version)
		v.CVSSVersion = c.version
		v.BaseScore = c.score
		v.BaseSeverity = classifySeverity(c.score)
		v.VectorString = c.vector
		return
	}
}

// classifySeverity maps a CVSS base score to the standard severity label.
//
//	NONE:     0.0
//	LOW:      0.1 – 3.9
//	MEDIUM:   4.0 – 6.9
//	HIGH:     7.0 – 8.9
//	CRITICAL: 9.0 – 10.0
func classifySeverity(score float32) string {
	switch {
	case score == 0.0:
		return "NONE"
	case score <= 3.9:
		return "LOW"
	case score <= 6.9:
		return "MEDIUM"
	case score <= 8.9:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}

// UpsertExploit inserts or updates an exploit
func (db *Database) UpsertExploit(ctx context.Context, exploit *models.Exploit) (int64, error) {
	query := `
		INSERT INTO exploits (
			source_name, title, author, type, platform,
			date_published, is_verified, poc_url,
			github_stars, db_updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP
		)
		ON CONFLICT (poc_url) DO UPDATE SET
			source_name = EXCLUDED.source_name,
			title = EXCLUDED.title,
			author = EXCLUDED.author,
			type = EXCLUDED.type,
			platform = EXCLUDED.platform,
			date_published = EXCLUDED.date_published,
			is_verified = EXCLUDED.is_verified,
			github_stars = EXCLUDED.github_stars,
			db_updated_at = CURRENT_TIMESTAMP
		RETURNING id
	`
	var id int64
	err := db.pool.QueryRow(ctx, query,
		exploit.SourceName,
		exploit.Title,
		exploit.Author,
		exploit.Type,
		exploit.Platform,
		exploit.DatePublished,
		exploit.IsVerified,
		exploit.PocURL,
		exploit.GithubStars,
	).Scan(&id)
	return id, err
}

// LinkExploitToCVE creates a link between an exploit and a CVE
func (db *Database) LinkExploitToCVE(ctx context.Context, exploitID int64, cveID string) error {
	query := `
		INSERT INTO vulnerability_exploits (cve_id, exploit_id)
		VALUES ($1, $2)
		ON CONFLICT (cve_id, exploit_id) DO NOTHING
	`
	_, err := db.pool.Exec(ctx, query, cveID, exploitID)
	return err
}

// GetExploitCount returns total count of exploits
func (db *Database) GetExploitCount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM exploits`
	var count int64
	err := db.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// GetExploitLinkCount returns total count of vulnerability-exploit links
func (db *Database) GetExploitLinkCount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM vulnerability_exploits`
	var count int64
	err := db.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// GetExploitsByCVE returns all exploits linked to a specific CVE
func (db *Database) GetExploitsByCVE(ctx context.Context, cveID string) ([]models.Exploit, error) {
	query := `
		SELECT e.id, e.source_name, e.title, e.author, e.type,
		       e.platform, e.date_published, e.is_verified, e.poc_url, e.github_stars
		FROM exploits e
		JOIN vulnerability_exploits ve ON e.id = ve.exploit_id
		WHERE ve.cve_id = $1
		ORDER BY e.date_published DESC
	`
	rows, err := db.pool.Query(ctx, query, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var exploits []models.Exploit
	for rows.Next() {
		var e models.Exploit
		err := rows.Scan(
			&e.ID, &e.SourceName, &e.Title, &e.Author, &e.Type,
			&e.Platform, &e.DatePublished, &e.IsVerified, &e.PocURL, &e.GithubStars,
		)
		if err != nil {
			return nil, err
		}
		exploits = append(exploits, e)
	}

	return exploits, rows.Err()
}

// GetOrphanExploitLinks returns CVE IDs that have exploits but don't exist in vulnerabilities
func (db *Database) GetOrphanExploitLinks(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT ve.cve_id
		FROM vulnerability_exploits ve
		LEFT JOIN vulnerabilities v ON ve.cve_id = v.cve_id
		WHERE v.cve_id IS NULL
		LIMIT 100
	`
	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cves []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		cves = append(cves, cve)
	}

	return cves, rows.Err()
}

// GetLinkedCVECount returns count of unique CVEs that have at least one exploit
func (db *Database) GetLinkedCVECount(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(DISTINCT cve_id) FROM vulnerability_exploits`
	var count int64
	err := db.pool.QueryRow(ctx, query).Scan(&count)
	return count, err
}

// UpsertVulnerability inserts or updates a single vulnerability
func (db *Database) UpsertVulnerability(ctx context.Context, vuln *models.Vulnerability) error {
	query := `
		INSERT INTO vulnerabilities (
			cve_id, source_name, description, published_date, last_modified_date,
			vuln_status, cvss_version, base_score, base_severity, vector_string, db_updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP
		)
		ON CONFLICT (cve_id) DO UPDATE SET
			source_name = EXCLUDED.source_name,
			description = EXCLUDED.description,
			published_date = EXCLUDED.published_date,
			last_modified_date = EXCLUDED.last_modified_date,
			vuln_status = EXCLUDED.vuln_status,
			cvss_version = EXCLUDED.cvss_version,
			base_score = EXCLUDED.base_score,
			base_severity = EXCLUDED.base_severity,
			vector_string = EXCLUDED.vector_string,
			db_updated_at = CURRENT_TIMESTAMP
		WHERE vulnerabilities.last_modified_date < EXCLUDED.last_modified_date
	`
	_, err := db.pool.Exec(ctx, query,
		vuln.CVEID,
		vuln.SourceName,
		vuln.Description,
		vuln.PublishedDate,
		vuln.LastModifiedDate,
		vuln.VulnStatus,
		vuln.CVSSVersion,
		vuln.BaseScore,
		vuln.BaseSeverity,
		vuln.VectorString,
	)
	return err
}
