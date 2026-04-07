using X4U.Domain.Interfaces;
using X4U.Infrastructure.Data;

namespace X4U.Infrastructure.Repositories;

public class UnitOfWork : IUnitOfWork
{
    private readonly AppDbContext _context;
    private IVulnerabilityRepository? _vulnerabilities;
    private IExploitRepository? _exploits;

    public UnitOfWork(AppDbContext context)
    {
        _context = context;
    }

    public IVulnerabilityRepository Vulnerabilities =>
        _vulnerabilities ??= new VulnerabilityRepository(_context);

    public IExploitRepository Exploits =>
        _exploits ??= new ExploitRepository(_context);

    public async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        return await _context.SaveChangesAsync(cancellationToken);
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}
