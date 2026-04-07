namespace X4U.Application.DTOs;

public record VulnerabilityFilterDto(
    string? CveId = null,
    int? CveYear = null,
    string? SourceName = null,
    string? DescriptionContains = null,
    string? VulnStatus = null,
    decimal? MinBaseScore = null,
    decimal? MaxBaseScore = null,
    string? BaseSeverity = null,
    string? CvssVersion = null,
    bool? HasExploit = null,
    string[]? SortBy = null,
    int PageSize = 50,
    string? Cursor = null
) : X4U.Application.Services.IPageSizeProvider, X4U.Application.Services.ICursorProvider;

public record ExploitFilterDto(
    string? SourceName = null,
    string? TitleContains = null,
    string? Author = null,
    string? Type = null,
    string? Platform = null,
    bool? IsVerified = null,
    string? CveId = null,
    int? MinGithubStars = null,
    string[]? SortBy = null,
    int PageSize = 50,
    string? Cursor = null
) : X4U.Application.Services.IPageSizeProvider, X4U.Application.Services.ICursorProvider;
