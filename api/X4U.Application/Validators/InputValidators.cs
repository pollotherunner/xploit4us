using System.Text.RegularExpressions;

namespace X4U.Application.Validators;

/// <summary>
/// Validator for exploit-related inputs
/// </summary>
public static class ExploitValidator
{
    private static readonly Regex NumericIdPattern = new(@"^\d+$", RegexOptions.Compiled);

    /// <summary>
    /// Validates if the external ID is a numeric string
    /// </summary>
    public static bool IsValidExternalId(string? externalId)
    {
        return !string.IsNullOrEmpty(externalId) && NumericIdPattern.IsMatch(externalId);
    }

    /// <summary>
    /// Validates external ID - must be numeric
    /// </summary>
    public static (bool IsValid, string? NormalizedId, string? ErrorMessage) ValidateAndNormalize(string? externalId)
    {
        if (string.IsNullOrEmpty(externalId))
        {
            return (false, null, "External ID is required");
        }

        var trimmed = externalId.Trim();

        if (NumericIdPattern.IsMatch(trimmed))
        {
            return (true, trimmed, null);
        }

        return (false, null, $"Invalid external ID format. Expected a numeric ID, got: {externalId}");
    }
}

/// <summary>
/// Validator for vulnerability-related inputs
/// </summary>
public static class VulnerabilityValidator
{
    private static readonly Regex CvePattern = new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Validates if the CVE ID is in the correct format (CVE-YYYY-XXXXX)
    /// </summary>
    public static bool IsValidCveId(string? cveId)
    {
        return !string.IsNullOrEmpty(cveId) && CvePattern.IsMatch(cveId);
    }

    /// <summary>
    /// Validates and normalizes CVE ID to uppercase
    /// </summary>
    public static (bool IsValid, string? NormalizedId, string? ErrorMessage) ValidateAndNormalize(string? cveId)
    {
        if (string.IsNullOrEmpty(cveId))
        {
            return (false, null, "CVE ID is required");
        }

        var normalized = cveId.Trim().ToUpper();
        
        if (!CvePattern.IsMatch(normalized))
        {
            return (false, null, $"Invalid CVE ID format. Expected format: CVE-YYYY-XXXXX, got: {cveId}");
        }

        return (true, normalized, null);
    }
}

/// <summary>
/// Validator for pagination parameters
/// </summary>
public static class PaginationValidator
{
    private const int MinPageSize = 1;
    private const int MaxPageSize = 200;
    private const int DefaultPageSize = 50;

    /// <summary>
    /// Validates and normalizes page size
    /// </summary>
    public static int ValidateAndNormalizePageSize(int? pageSize)
    {
        if (!pageSize.HasValue || pageSize.Value < MinPageSize)
        {
            return DefaultPageSize;
        }

        if (pageSize.Value > MaxPageSize)
        {
            return MaxPageSize;
        }

        return pageSize.Value;
    }

    /// <summary>
    /// Validates sort by field against allowed values
    /// </summary>
    public static bool IsValidSortField(string? sortBy, IEnumerable<string> allowedFields)
    {
        if (string.IsNullOrEmpty(sortBy))
            return true;

        return allowedFields.Contains(sortBy, StringComparer.OrdinalIgnoreCase);
    }
}
