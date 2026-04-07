using Microsoft.EntityFrameworkCore;
using X4U.Domain.Entities;

namespace X4U.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<Exploit> Exploits => Set<Exploit>();
    public DbSet<VulnerabilityExploit> VulnerabilityExploits => Set<VulnerabilityExploit>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Vulnerability>(entity =>
        {
            entity.ToTable("vulnerabilities");
            entity.HasKey(v => v.CveId);
            entity.Property(v => v.CveId).HasColumnName("cve_id").HasMaxLength(25).IsRequired();
            entity.Property(v => v.SourceName).HasColumnName("source_name").HasMaxLength(50).IsRequired();
            entity.Property(v => v.Description).HasColumnName("description").IsRequired();
            entity.Property(v => v.PublishedDate).HasColumnName("published_date");
            entity.Property(v => v.LastModifiedDate).HasColumnName("last_modified_date");
            entity.Property(v => v.VulnStatus).HasColumnName("vuln_status").HasMaxLength(50);
            entity.Property(v => v.CvssVersion).HasColumnName("cvss_version").HasMaxLength(10);
            entity.Property(v => v.BaseScore).HasColumnName("base_score").HasPrecision(3, 1);
            entity.Property(v => v.BaseSeverity).HasColumnName("base_severity").HasMaxLength(20);
            entity.Property(v => v.VectorString).HasColumnName("vector_string").HasColumnType("text");
            entity.Property(v => v.DbUpdatedAt).HasColumnName("db_updated_at");

            entity.HasIndex(v => v.LastModifiedDate);
            entity.HasIndex(v => v.PublishedDate);
            entity.HasIndex(v => v.BaseSeverity);
            entity.HasIndex(v => v.BaseScore);
        });

        modelBuilder.Entity<Exploit>(entity =>
        {
            entity.ToTable("exploits");
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasColumnName("id").IsRequired();
            entity.Property(e => e.SourceName).HasColumnName("source_name").HasMaxLength(50).IsRequired();
            entity.Property(e => e.Title).HasColumnName("title").IsRequired();
            entity.Property(e => e.Author).HasColumnName("author");
            entity.Property(e => e.Type).HasColumnName("type").HasMaxLength(50);
            entity.Property(e => e.Platform).HasColumnName("platform").HasMaxLength(100);
            entity.Property(e => e.DatePublished).HasColumnName("date_published");
            entity.Property(e => e.IsVerified).HasColumnName("is_verified");
            entity.Property(e => e.PocUrl).HasColumnName("poc_url").IsRequired();
            entity.Property(e => e.GithubStars).HasColumnName("github_stars");
            entity.Property(e => e.DbUpdatedAt).HasColumnName("db_updated_at");

            entity.HasIndex(e => e.PocUrl);
            entity.HasIndex(e => e.DatePublished);
            entity.HasIndex(e => e.IsVerified);
            entity.HasIndex(e => e.Platform);
        });

        modelBuilder.Entity<VulnerabilityExploit>(entity =>
        {
            entity.ToTable("vulnerability_exploits");
            entity.HasKey(ve => new { ve.CveId, ve.ExploitId });

            entity.Property(ve => ve.CveId).HasColumnName("cve_id");
            entity.Property(ve => ve.ExploitId).HasColumnName("exploit_id");
            entity.Property(ve => ve.LinkedAt).HasColumnName("linked_at");

            entity.HasOne(ve => ve.Vulnerability)
                .WithMany(v => v.VulnerabilityExploits)
                .HasForeignKey(ve => ve.CveId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(ve => ve.Exploit)
                .WithMany(e => e.VulnerabilityExploits)
                .HasForeignKey(ve => ve.ExploitId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(ve => ve.CveId);
            entity.HasIndex(ve => ve.ExploitId);
        });
    }
}
