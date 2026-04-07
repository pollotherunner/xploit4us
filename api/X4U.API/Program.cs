using X4U.API.Extensions;
using X4U.Application.DTOs;
using X4U.Application.Services;
using X4U.Application.Validators;
using X4U.Domain.Interfaces;
using X4U.Infrastructure.Data;
using X4U.Infrastructure.Repositories;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// Database
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Repositories and Unit of Work
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

// Application Services
builder.Services.AddScoped<IVulnerabilityService, VulnerabilityService>();
builder.Services.AddScoped<IExploitService, ExploitService>();

// HttpClient for external API calls with proper configuration
builder.Services.AddHttpClient("ExploitDbClient")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = true,
        UseCookies = false
    });

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseDefaultFiles();
app.UseStaticFiles();

// Vulnerability endpoints
app.MapGet("/api/vulnerabilities", GetVulnerabilities)
    .WithName("GetVulnerabilities")
    .WithTags("Vulnerabilities");

app.MapGet("/api/vulnerabilities/{cveId}", GetVulnerabilityById)
    .WithName("GetVulnerabilityById")
    .WithTags("Vulnerabilities");

app.MapGet("/api/vulnerabilities/{cveId}/exploits", GetVulnerabilityWithExploits)
    .WithName("GetVulnerabilityWithExploits")
    .WithTags("Vulnerabilities");

// Exploit endpoints
app.MapGet("/api/exploits", GetExploits)
    .WithName("GetExploits")
    .WithTags("Exploits");

app.MapGet("/api/exploits/{id}", GetExploitById)
    .WithName("GetExploitById")
    .WithTags("Exploits");

app.MapGet("/api/exploits/{id}/vulnerabilities", GetExploitWithVulnerabilities)
    .WithName("GetExploitWithVulnerabilities")
    .WithTags("Exploits");

app.MapGet("/api/exploits/{id}/code", GetExploitCode)
    .WithName("GetExploitCode")
    .WithTags("Exploits");

// Health check
app.MapGet("/api/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithTags("Health");

app.Run();

// ============================================================================
// Endpoint Handlers
// ============================================================================

async Task<IResult> GetVulnerabilities(
    string? CveId = null,
    int? CveYear = null,
    string? SourceName = null,
    string? DescriptionContains = null,
    string? VulnStatus = null,
    decimal? MinBaseScore = null,
    decimal? MaxBaseScore = null,
    string? BaseSeverity = null,
    string? CvssVersion = null,
    string? HasExploit = null,
    string[]? SortBy = null,
    int PageSize = 50,
    string? Cursor = null,
    IVulnerabilityService? service = null,
    CancellationToken cancellationToken = default)
{
    bool? hasExploitBool = null;
    if (HasExploit == "true") hasExploitBool = true;
    else if (HasExploit == "false") hasExploitBool = false;

    var filter = new VulnerabilityFilterDto(
        CveId: CveId,
        CveYear: CveYear,
        SourceName: SourceName,
        DescriptionContains: DescriptionContains,
        VulnStatus: VulnStatus,
        MinBaseScore: MinBaseScore,
        MaxBaseScore: MaxBaseScore,
        BaseSeverity: BaseSeverity,
        CvssVersion: CvssVersion,
        HasExploit: hasExploitBool,
        SortBy: SortBy,
        PageSize: PageSize,
        Cursor: Cursor
    );

    var result = await service!.FilterAsync(filter, cancellationToken);
    return Results.Ok(result);
}

async Task<IResult> GetVulnerabilityById(
    string cveId,
    IVulnerabilityService service,
    HttpContext httpContext,
    CancellationToken cancellationToken)
{
    var (isValid, _, errorMessage) = VulnerabilityValidator.ValidateAndNormalize(cveId);
    if (!isValid)
    {
        return httpContext.ProblemNotFound(errorMessage ?? "Invalid CVE ID");
    }

    var result = await service.GetByIdAsync(cveId, cancellationToken);
    return result is not null ? Results.Ok(result) : Results.NotFound();
}

async Task<IResult> GetVulnerabilityWithExploits(
    string cveId,
    IVulnerabilityService service,
    CancellationToken cancellationToken)
{
    var result = await service.GetExploitsByVulnerabilityAsync(cveId, cancellationToken);
    return Results.Ok(result);
}

async Task<IResult> GetExploits(
    string? SourceName = null,
    string? TitleContains = null,
    string? Author = null,
    string? Type = null,
    string? Platform = null,
    string? IsVerified = null,
    string? CveId = null,
    int? MinGithubStars = null,
    string[]? SortBy = null,
    int PageSize = 50,
    string? Cursor = null,
    IExploitService? service = null,
    CancellationToken cancellationToken = default)
{
    bool? isVerifiedBool = null;
    if (IsVerified == "true") isVerifiedBool = true;
    else if (IsVerified == "false") isVerifiedBool = false;

    var filter = new ExploitFilterDto(
        SourceName: SourceName,
        TitleContains: TitleContains,
        Author: Author,
        Type: Type,
        Platform: Platform,
        IsVerified: isVerifiedBool,
        CveId: CveId,
        MinGithubStars: MinGithubStars,
        SortBy: SortBy,
        PageSize: PageSize,
        Cursor: Cursor
    );

    var result = await service!.FilterAsync(filter, cancellationToken);
    return Results.Ok(result);
}

async Task<IResult> GetExploitById(
    int id,
    IExploitService service,
    CancellationToken cancellationToken)
{
    var result = await service.GetByIdAsync(id.ToString(), cancellationToken);
    return result is not null ? Results.Ok(result) : Results.NotFound();
}

async Task<IResult> GetExploitWithVulnerabilities(
    int id,
    IExploitService service,
    CancellationToken cancellationToken)
{
    var result = await service.GetVulnerabilitiesByExploitAsync(id.ToString(), cancellationToken);
    return Results.Ok(result);
}

async Task<IResult> GetExploitCode(
    int id,
    IExploitService service,
    CancellationToken cancellationToken)
{
    var code = await service.GetExploitCodeAsync(id.ToString(), cancellationToken);
    return code is not null ? Results.Ok(new ExploitCodeResponse(code)) : Results.NotFound();
}

// ============================================================================
// Response DTOs
// ============================================================================

public record ExploitCodeResponse(string Code);


