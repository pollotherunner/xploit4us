namespace X4U.Application.DTOs;

public record VulnerabilityDto(
    string CveId,
    string SourceName,
    string Description,
    DateTime? PublishedDate,
    DateTime? LastModifiedDate,
    string? VulnStatus,
    string? CvssVersion,
    decimal? BaseScore,
    string? BaseSeverity,
    string? VectorString,
    DateTime DbUpdatedAt,
    bool HasExploit,
    int ExploitsCount
);

public record ExploitDto(
    int Id,
    string SourceName,
    string Title,
    string? Author,
    string? Type,
    string? Platform,
    DateTime? DatePublished,
    bool IsVerified,
    string PocUrl,
    DateTime DbUpdatedAt,
    int VulnerabilitiesCount,
    int GithubStars = 0
);

public record VulnerabilityExploitDto(
    string CveId,
    string ExploitExternalId,
    DateTime LinkedAt
);
