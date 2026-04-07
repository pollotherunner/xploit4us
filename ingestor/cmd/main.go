package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"log/slog"

	"xploit4us-ingestor/internal/config"
	"xploit4us-ingestor/internal/database"
	"xploit4us-ingestor/internal/exploitdb"
	"xploit4us-ingestor/internal/github"
	"xploit4us-ingestor/internal/models"
	"xploit4us-ingestor/internal/nist"
	"xploit4us-ingestor/pkg/logger"

	"github.com/joho/godotenv"
)

const helpText = `
xploit4us Ingestor - Vulnerability and Exploit Data Ingestion Tool

USAGE:
    ingestor [COMMAND] [OPTIONS]

COMMANDS:
    (no command)     Show this help message
    nist             NIST NVD ingestor only
    exploitdb        ExploitDB ingestor only
    github           GitHub PoC ingestor only (PoC-in-GitHub)
    all              All ingestors

OPTIONS:
    --resync-all     Force full resync of ALL data (NIST + ExploitDB + GitHub).
                     DANGER: This will re-download and re-insert everything from scratch.
    --resync         Force full resync of the specified ingestor only.
                     Use with 'nist', 'exploitdb' or 'github' command.
    --sync, -s       Run incremental sync (default behavior).
                     Only fetches new/modified data since last sync.
    --help, -h       Show this help message

`

func main() {
	// Load .env file from project root
	envPaths := []string{".env", "../.env"}
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			fmt.Printf("Loaded .env from: %s\n", path)
			break
		}
	}

	// Check for help flag or no arguments
	if len(os.Args) == 1 {
		fmt.Println(helpText)
		os.Exit(0)
	}

	// Check for help flag anywhere in args
	for _, arg := range os.Args {
		if arg == "--help" || arg == "-h" {
			fmt.Println(helpText)
			os.Exit(0)
		}
	}

	// Check flags directly from os.Args (before flag.Parse)
	hasFlag := func(flags ...string) bool {
		for _, arg := range os.Args {
			for _, f := range flags {
				if arg == f {
					return true
				}
			}
		}
		return false
	}

	resyncAll := hasFlag("--resync-all")
	resync := hasFlag("--resync")
	syncFlag := hasFlag("--sync", "-s")

	// Determine command (first non-flag argument)
	var command string
	for _, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			command = arg
			break
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		cancel()
	}()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format)

	// Connect to database
	db, err := database.New(ctx, cfg.Database.DSN())
	if err != nil {
		log.Error("Failed to connect to database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer db.Close()

	// Initialize schema
	if err := db.InitSchema(ctx); err != nil {
		log.Error("Failed to initialize schema", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Determine what to run based on command and flags
	runNIST := false
	runExploitDB := false
	runGitHub := false
	forceNIST := false
	forceExploitDB := false
	forceGitHub := false

	// Handle commands and flags together
	switch command {
	case "nist":
		runNIST = true
		forceNIST = resync || resyncAll
	case "exploitdb":
		runExploitDB = true
		forceExploitDB = resync || resyncAll
	case "github":
		runGitHub = true
		forceGitHub = resync || resyncAll
	case "all":
		runNIST = true
		runExploitDB = true
		runGitHub = true
		forceNIST = resyncAll
		forceExploitDB = resyncAll
		forceGitHub = resyncAll
	case "":
		// No command specified, use flags
		if resyncAll {
			runNIST = true
			runExploitDB = true
			runGitHub = true
			forceNIST = true
			forceExploitDB = true
			forceGitHub = true
		} else if resync {
			// --resync without command defaults to all
			runNIST = true
			runExploitDB = true
			runGitHub = true
			forceNIST = true
			forceExploitDB = true
			forceGitHub = true
		} else if syncFlag || (!resyncAll && !resync) {
			// Default: incremental sync for all
			runNIST = true
			runExploitDB = true
			runGitHub = true
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		fmt.Println(helpText)
		os.Exit(1)
	}

	// Run NIST ingestor
	if runNIST {
		mode := "INCREMENTAL"
		if forceNIST {
			mode = "FULL SYNC"
		}
		log.Info("Starting NIST NVD Ingestor", slog.String("mode", mode))
		runNISTIngestor(ctx, db, cfg, log, forceNIST)
	}

	// Run ExploitDB ingestor
	if runExploitDB {
		mode := "INCREMENTAL"
		if forceExploitDB {
			mode = "FULL SYNC"
		}
		log.Info("Starting ExploitDB Ingestor", slog.String("mode", mode))
		runExploitDBIngestor(ctx, db, cfg, log, forceExploitDB)
	}

	// Run GitHub PoC ingestor
	if runGitHub {
		mode := "FULL SYNC"
		log.Info("Starting GitHub PoC Ingestor", slog.String("mode", mode))
		runGitHubIngestor(ctx, db, log, forceGitHub)
	}

	log.Info("All ingestors completed")
}

func runNISTIngestor(ctx context.Context, db *database.Database, cfg *config.Config, log *slog.Logger, forceFullSync bool) {
	// Get existing count
	existingCount, err := db.GetVulnerabilityCount(ctx)
	if err != nil {
		log.Error("Failed to get vulnerability count", slog.String("error", err.Error()))
		return
	}
	log.Info("Database status", slog.Int64("existing_records", existingCount))

	// Create NIST client
	nistClient := nist.NewClient(cfg.NIST, log)

	// Get total count from NIST API for reporting
	log.Info("Checking total vulnerabilities in NIST API...")
	initResp, _, err := nistClient.FetchVulnerabilitiesWithFilters(ctx, 0, "", "")
	if err != nil {
		log.Error("Failed to get total count from NIST", slog.String("error", err.Error()))
		return
	}
	totalInNIST := initResp.TotalResults
	log.Info("NIST API total", slog.Int("total_vulnerabilities", totalInNIST))

	// Check sync history to determine mode
	hasCompletedFullSync, err := db.HasCompletedFullSync(ctx)
	if err != nil {
		log.Warn("Failed to check sync history", slog.String("error", err.Error()))
	}

	// Get the full sync start date (if exists)
	fullSyncStartDate, err := db.GetFullSyncStartDate(ctx)
	if err != nil {
		log.Warn("Failed to get full sync start date", slog.String("error", err.Error()))
	}

	// Determine sync mode and date range
	var lastModStart, lastModEnd string
	var isFullSync bool

	if forceFullSync {
		isFullSync = true
		log.Info("FULL SYNC forced via --resync-vuln or --resync-all flag",
			slog.Int("total_to_fetch", totalInNIST),
		)
	} else if !hasCompletedFullSync {
		// First time or never completed full sync - do FULL SYNC
		isFullSync = true
		log.Info("FIRST RUN: Starting FULL SYNC to populate database",
			slog.Int("total_to_fetch", totalInNIST),
			slog.Int64("already_in_db", existingCount),
		)
		// Mark that full sync started
		if err := db.MarkFullSyncStarted(ctx); err != nil {
			log.Warn("Failed to mark full sync start", slog.String("error", err.Error()))
		}
	} else if fullSyncStartDate != nil {
		// Already did full sync - do INCREMENTAL since full sync started
		isFullSync = false
		// Start from 1 second after the full sync started
		lastModStart = fullSyncStartDate.Add(1 * time.Second).Format("2006-01-02T15:04:05.000")
		lastModEnd = time.Now().Format("2006-01-02T15:04:05.000")
		log.Info("INCREMENTAL mode: fetching vulnerabilities modified since last full sync",
			slog.Time("since", *fullSyncStartDate),
			slog.String("until", lastModEnd),
		)
	} else {
		// Fallback to full sync
		isFullSync = true
		log.Info("FULL SYNC mode (fallback)",
			slog.Int("total_to_fetch", totalInNIST),
		)
	}

	// Mark full sync start if doing full sync
	if isFullSync {
		if err := db.MarkFullSyncStarted(ctx); err != nil {
			log.Warn("Failed to mark full sync start", slog.String("error", err.Error()))
		}
	}

	// Track statistics
	var totalProcessed, totalUpserted int

	// Fetch and ingest vulnerabilities
	err = nistClient.FetchAllVulnerabilities(ctx, lastModStart, lastModEnd, func(vulns []models.NISTVulnerability, _ []json.RawMessage) error {
		batch := make([]*models.Vulnerability, 0, len(vulns))

		for _, vuln := range vulns {
			parsedVuln := database.ParseNISTVulnerability(vuln)
			batch = append(batch, parsedVuln)
		}

		upserted, err := db.UpsertVulnerabilitiesBatch(ctx, batch, isFullSync)
		if err != nil {
			return err
		}

		totalProcessed += len(batch)
		totalUpserted += upserted

		log.Info("Batch processed",
			slog.Int("batch_size", len(batch)),
			slog.Int("upserted", upserted),
			slog.Int("total_processed", totalProcessed),
		)

		return nil
	})

	if err != nil {
		log.Error("Failed to fetch vulnerabilities", slog.String("error", err.Error()))
		return
	}

	// Mark sync as completed
	if err := db.MarkFullSyncCompleted(ctx); err != nil {
		log.Warn("Failed to mark sync as completed", slog.String("error", err.Error()))
	}

	// Get final count
	finalCount, err := db.GetVulnerabilityCount(ctx)
	if err != nil {
		log.Error("Failed to get final count", slog.String("error", err.Error()))
		return
	}

	log.Info("NIST ingestion completed successfully",
		slog.Int("total_processed", totalProcessed),
		slog.Int("total_upserted", totalUpserted),
		slog.Int64("total_in_db", finalCount),
		slog.Bool("was_full_sync", isFullSync),
	)
}

func runExploitDBIngestor(ctx context.Context, db *database.Database, cfg *config.Config, log *slog.Logger, forceFullSync bool) {
	// Check existing data
	exploitCount, err := db.GetExploitCount(ctx)
	if err != nil {
		log.Error("Failed to get exploit count", slog.String("error", err.Error()))
		return
	}

	linkCount, err := db.GetExploitLinkCount(ctx)
	if err != nil {
		log.Error("Failed to get link count", slog.String("error", err.Error()))
		return
	}

	if !forceFullSync && exploitCount > 0 {
		log.Info("Exploits already exist in database, skipping (use 'exploitdb --resync' to force)",
			slog.Int64("exploit_count", exploitCount),
			slog.Int64("link_count", linkCount),
		)
		return
	}

	if forceFullSync {
		log.Info("Force flag set, will re-import all exploits")
	}

	// Create ExploitDB client
	client := exploitdb.NewClient(log)

	// Fetch and process exploits
	if err := client.FetchAndProcess(ctx, db); err != nil {
		log.Error("Failed to process exploits", slog.String("error", err.Error()))
		return
	}

	// Get final counts
	finalExploitCount, err := db.GetExploitCount(ctx)
	if err != nil {
		log.Error("Failed to get final exploit count", slog.String("error", err.Error()))
		return
	}

	finalLinkCount, err := db.GetExploitLinkCount(ctx)
	if err != nil {
		log.Error("Failed to get final link count", slog.String("error", err.Error()))
		return
	}

	// Check for orphan links (CVEs in exploits that don't exist in vulnerabilities)
	orphanCVEs, err := db.GetOrphanExploitLinks(ctx)
	if err != nil {
		log.Warn("Failed to check for orphan links", slog.String("error", err.Error()))
	}

	linkedCVECount, err := db.GetLinkedCVECount(ctx)
	if err != nil {
		log.Error("Failed to get linked CVE count", slog.String("error", err.Error()))
		return
	}

	log.Info("ExploitDB ingestion completed successfully",
		slog.Int64("total_exploits", finalExploitCount),
		slog.Int64("total_links", finalLinkCount),
		slog.Int64("unique_cves_with_exploits", linkedCVECount),
		slog.Int("orphan_cve_links", len(orphanCVEs)),
	)

	if len(orphanCVEs) > 0 {
		log.Info("Orphan CVE links found (exploits reference CVEs not in NIST database)",
			slog.Any("example_cves", orphanCVEs[:min(10, len(orphanCVEs))]),
		)
	}
}

func runGitHubIngestor(ctx context.Context, db *database.Database, log *slog.Logger, forceFullSync bool) {
	// Create GitHub PoC client
	client := github.NewClient(log)

	// Fetch and process PoCs from GitHub
	if err := client.FetchAndProcess(ctx, db); err != nil {
		log.Error("Failed to process GitHub PoCs", slog.String("error", err.Error()))
		return
	}

	// Get final counts
	finalExploitCount, err := db.GetExploitCount(ctx)
	if err != nil {
		log.Error("Failed to get final exploit count", slog.String("error", err.Error()))
		return
	}

	finalLinkCount, err := db.GetExploitLinkCount(ctx)
	if err != nil {
		log.Error("Failed to get final link count", slog.String("error", err.Error()))
		return
	}

	linkedCVECount, err := db.GetLinkedCVECount(ctx)
	if err != nil {
		log.Error("Failed to get linked CVE count", slog.String("error", err.Error()))
		return
	}

	log.Info("GitHub PoC ingestion completed successfully",
		slog.Int64("total_exploits", finalExploitCount),
		slog.Int64("total_links", finalLinkCount),
		slog.Int64("unique_cves_with_pocs", linkedCVECount),
	)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
