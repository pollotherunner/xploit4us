<div align="center">
  <img src="api/X4U.API/wwwroot/images/logo.png" alt="xploit4us Logo" width="500">

  # xploit4us

  Search engine and unified indexer for vulnerabilities and public exploits.<br>
![.NET](https://img.shields.io/badge/.NET-512BD4?style=flat-square&logo=dotnet&logoColor=white)
  ![Go](https://img.shields.io/badge/Go-00ADD8?style=flat-square&logo=go&logoColor=white)
  ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=flat-square&logo=postgresql&logoColor=white)
  ![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=flat-square&logo=docker&logoColor=white)
  <br>
  ![GitHub](https://img.shields.io/badge/NVD-black?style=flat-square)
  ![ExploitDb](https://img.shields.io/badge/ExploitDB-fd7e14?style=flat-square)
  ![GitHub](https://img.shields.io/badge/Github-151b23?style=flat-square&logo=github&logoColor=white)
</div>

## Quick Start

```bash
git clone https://github.com/pollotherunner/xploit4us.git xploit4us && cd xploit4us && cp .env.example .env && docker compose up -d && until docker compose exec x4u_db pg_isready -U postgres; do sleep 1; done && cd ingestor && go run cmd/main.go all --resync && cd ../api && dotnet run --project X4U.API
```

Then access the API at `http://localhost:5212`.

## Overview

xploit4us aggregates CVE data from NIST NVD, ExploitDB, and GitHub PoC repositories into a single searchable platform. It provides a REST API with keyset pagination, multi-criteria filtering, and a lightweight web UI served directly from the API.


The system has three components:

- **API** - ASP.NET Core 10.0 Minimal APIs, read-only query interface with multi-sort, keyset pagination, and advanced filtering
- **Ingestor** - Go CLI that pulls and syncs data from external sources (NIST NVD, ExploitDB, GitHub)
- **Database** - PostgreSQL 16

## Dependencies

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [Go 1.26+](https://golang.org/dl/)
- [Docker & Docker Compose](https://docs.docker.com/)

## Tech Stack

| Component | Stack |
|-----------|-------|
| API | ASP.NET Core 10.0 Minimal APIs, EF Core 10, PostgreSQL |
| Ingestor | Go 1.26 with pgx/v5 |
| Frontend | Vanilla HTML5/CSS3/JavaScript, Highlight.js |
| Infrastructure | Docker Compose (PostgreSQL 16 + Adminer) |

## Architecture

```
xploit4us/
├── api/                  # ASP.NET Core 10.0
│   ├── X4U.API/          # API layer, minimal APIs, wwwroot
│   ├── X4U.Application/  # Services, DTOs, validators
│   ├── X4U.Domain/       # Entities, interfaces
│   └── X4U.Infrastructure/  # EF Core, repositories
├── ingestor/             # Go CLI
│   ├── cmd/main.go       # Entry point
│   └── internal/         # Database, NIST, ExploitDB, GitHub
├── Dockerfile.API        # Containerized API build
├── Dockerfile.ingestor   # Containerized ingestor build
└── docker-compose.yml    # Full stack (PostgreSQL, Adminer, API, Ingestor)
```

## Running the Application

```bash
# Start database and adminer
docker compose up -d postgres adminer

# Load data
cd ingestor && go run cmd/main.go all --resync

# Run API
cd ../api && dotnet run --project X4U.API
```

### Access points

| Service | URL |
|---------|-----|
| Web UI | http://localhost:5212 |
| API docs | http://localhost:5212/scalar |
| Adminer | http://localhost:8080 |

## API Endpoints

All endpoints are read-only. Filtering and pagination use query parameters.

**Vulnerabilities**

| Method | Path | Description |
|:-------|:-----|:------------|
| GET | `/api/vulnerabilities` | List with filtering |
| GET | `/api/vulnerabilities/{cveId}` | Single vulnerability |
| GET | `/api/vulnerabilities/{cveId}/exploits` | Related exploits |

**Exploits**

| Method | Path | Description |
|:-------|:-----|:------------|
| GET | `/api/exploits` | List with filtering |
| GET | `/api/exploits/{id}` | Single exploit |
| GET | `/api/exploits/{id}/vulnerabilities` | Related vulnerabilities |
| GET | `/api/exploits/{id}/code` | Raw exploit source code |

**Health**

| Method | Path | Description |
|:-------|:-----|:------------|
| GET | `/api/health` | Service health status |


## Ingestor Commands

```bash
go run cmd/main.go --help
```

The first run requires `--resync`. Subsequent runs use incremental sync by default.
