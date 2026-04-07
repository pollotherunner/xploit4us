namespace X4U.Application.DTOs;

public record VulnerabilitiesResponse(
    IEnumerable<VulnerabilityDto> Items,
    int TotalCount,
    string? NextCursor,
    string? PreviousCursor,
    int PageSize,
    bool HasMore
);

public record ExploitsResponse(
    IEnumerable<ExploitDto> Items,
    int TotalCount,
    string? NextCursor,
    string? PreviousCursor,
    int PageSize,
    bool HasMore
);

public record PagedResult<T>(
    IEnumerable<T> Items,
    int TotalCount,
    string? NextCursor,
    string? PreviousCursor,
    int PageSize,
    bool HasMore
);
