using Microsoft.AspNetCore.Http;

namespace X4U.API.Extensions;

/// <summary>
/// Extension methods for creating standardized ProblemDetails responses
/// </summary>
public static class ProblemDetailsExtensions
{
    /// <summary>
    /// Creates a ProblemDetails result for bad request errors
    /// </summary>
    public static IResult ProblemBadRequest(
        this HttpContext context,
        string detail,
        string? instance = null)
    {
        return Results.Problem(
            detail: detail,
            statusCode: StatusCodes.Status400BadRequest,
            type: "https://tools.ietf.org/html/rfc7231#section-6.5.1",
            title: "Bad Request",
            instance: instance,
            extensions: new Dictionary<string, object?>
            {
                ["traceId"] = context.TraceIdentifier
            }
        );
    }

    /// <summary>
    /// Creates a ProblemDetails result for not found errors
    /// </summary>
    public static IResult ProblemNotFound(
        this HttpContext context,
        string detail,
        string? instance = null)
    {
        return Results.Problem(
            detail: detail,
            statusCode: StatusCodes.Status404NotFound,
            type: "https://tools.ietf.org/html/rfc7231#section-6.5.4",
            title: "Not Found",
            instance: instance,
            extensions: new Dictionary<string, object?>
            {
                ["traceId"] = context.TraceIdentifier
            }
        );
    }

    /// <summary>
    /// Creates a ProblemDetails result for internal server errors
    /// </summary>
    public static IResult ProblemInternalServerError(
        this HttpContext context,
        string detail,
        string? instance = null)
    {
        return Results.Problem(
            detail: "An error occurred while processing your request.",
            statusCode: StatusCodes.Status500InternalServerError,
            type: "https://tools.ietf.org/html/rfc7231#section-6.6.1",
            title: "Internal Server Error",
            instance: instance,
            extensions: new Dictionary<string, object?>
            {
                ["traceId"] = context.TraceIdentifier
            }
        );
    }

    /// <summary>
    /// Creates a ProblemDetails result for validation errors
    /// </summary>
    public static IResult ProblemValidation(
        this HttpContext context,
        string detail,
        Dictionary<string, string>? errors = null,
        string? instance = null)
    {
        var extensions = new Dictionary<string, object?>
        {
            ["traceId"] = context.TraceIdentifier
        };

        if (errors != null && errors.Count > 0)
        {
            extensions["errors"] = errors;
        }

        return Results.Problem(
            detail: detail,
            statusCode: StatusCodes.Status422UnprocessableEntity,
            type: "https://tools.ietf.org/html/rfc4918#section-11.2",
            title: "Validation Error",
            instance: instance,
            extensions: extensions
        );
    }
}

/// <summary>
/// Standardized API response helper
/// </summary>
public static class ApiResponse
{
    /// <summary>
    /// Creates a standardized error response for invalid input
    /// </summary>
    public static IResult InvalidInput(string fieldName, string message)
    {
        return Results.ValidationProblem(
            new Dictionary<string, string[]> { [fieldName] = [message] },
            title: "Invalid Input",
            type: "https://tools.ietf.org/html/rfc7807#section-3.1"
        );
    }

    /// <summary>
    /// Creates a standardized error response for not found
    /// </summary>
    public static IResult NotFound(string resource, string? identifier = null)
    {
        var detail = identifier != null 
            ? $"{resource} with identifier '{identifier}' was not found" 
            : $"{resource} was not found";

        return Results.Problem(
            detail: detail,
            statusCode: StatusCodes.Status404NotFound,
            type: "https://tools.ietf.org/html/rfc7231#section-6.5.4",
            title: "Not Found"
        );
    }
}
