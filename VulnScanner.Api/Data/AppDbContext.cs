using Microsoft.EntityFrameworkCore;
using VulnScanner.Api.Models;

namespace VulnScanner.Api.Data;

public class AppDbContext : DbContext
{
  public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
  
  public DbSet<ScanResult> ScanResults { get; set; }
  public DbSet<Vulnerability> Vulnerabilities { get; set; }
}
