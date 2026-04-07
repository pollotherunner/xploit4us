namespace X4U.Domain.Interfaces;

public interface IUnitOfWork : IDisposable
{
    IVulnerabilityRepository Vulnerabilities { get; }
    IExploitRepository Exploits { get; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}
