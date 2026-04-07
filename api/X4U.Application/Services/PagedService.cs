using X4U.Application.DTOs;
using X4U.Domain.Interfaces;

namespace X4U.Application.Services;

/// <summary>
/// Interface for filters that provide page size
/// </summary>
public interface IPageSizeProvider
{
    int PageSize { get; }
}

/// <summary>
/// Interface for filters that provide cursor
/// </summary>
public interface ICursorProvider
{
    string? Cursor { get; }
}

/// <summary>
/// Helper class for common pagination logic across services
/// </summary>
public static class PaginationHelper
{
    public static async Task<(IEnumerable<TDto> Items, int TotalCount, string? NextCursor, bool HasMore)> 
        ExecutePaginationAsync<TEntity, TDto, TFilter>(
            TFilter filter,
            Func<TFilter, string?, int, CancellationToken, Task<(IEnumerable<TEntity> Items, string? NextKey)>> queryFunc,
            Func<TFilter, CancellationToken, Task<int>> countFunc,
            Func<TEntity, TDto> mapToDto,
            CancellationToken cancellationToken = default)
    {
        var (items, nextKey) = await queryFunc(filter, GetCursor(filter), GetPageSize(filter), cancellationToken);
        var totalCount = await countFunc(filter, cancellationToken);
        var hasNext = items.Count() == GetPageSize(filter);

        var dtoItems = items.Select(mapToDto);

        return (dtoItems, totalCount, nextKey, hasNext);
    }

    public static async Task<(IEnumerable<TDto> Items, int TotalCount, string? NextCursor, bool HasMore)> 
        ExecutePaginationWithDomainFilterAsync<TEntity, TDto, TFilterDto, TFilterDomain>(
            TFilterDto filterDto,
            TFilterDomain domainFilter,
            Func<TFilterDomain, string?, int, CancellationToken, Task<(IEnumerable<TEntity> Items, string? NextKey)>> queryFunc,
            Func<TFilterDomain, CancellationToken, Task<int>> countFunc,
            Func<TEntity, TDto> mapToDto,
            CancellationToken cancellationToken = default)
            where TFilterDto : IPageSizeProvider, ICursorProvider
        {
            var (items, nextKey) = await queryFunc(domainFilter, filterDto.Cursor, filterDto.PageSize, cancellationToken);
            var totalCount = await countFunc(domainFilter, cancellationToken);
            var hasNext = items.Count() == filterDto.PageSize;

            var dtoItems = items.Select(mapToDto);

            return (dtoItems, totalCount, nextKey, hasNext);
        }

    private static int GetPageSize<TFilter>(TFilter filter)
    {
        return filter switch
        {
            IPageSizeProvider p => p.PageSize,
            _ => 50
        };
    }

    private static string? GetCursor<TFilter>(TFilter filter)
    {
        return filter switch
        {
            ICursorProvider c => c.Cursor,
            _ => null
        };
    }
}
