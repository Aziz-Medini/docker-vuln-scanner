using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;
using VulnScanner.Api.Data;
using VulnScanner.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace VulnScanner.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ScanController : ControllerBase
{
    private readonly AppDbContext _context;

    public ScanController(AppDbContext context)
    {
        _context = context;
    }

    [HttpGet("{imageName}")]
    public async Task<IActionResult> ScanImage(string imageName, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "trivy",
            Arguments = $"image {imageName} --scanners vuln --skip-version-check --format json",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        string output;
        string error;

        try
        {
            output = await process!.StandardOutput.ReadToEndAsync(cancellationToken);
            error = await process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            if (!process!.HasExited)
            {
                try { process.Kill(true); } catch { /* already exited */ }
            }
            throw;
        }

        if (process.ExitCode != 0)
        {
            return StatusCode(500, new { error });
        }

        TrivyReport? report;
        try
        {
            report = JsonSerializer.Deserialize<TrivyReport>(output);
        }
        catch (JsonException ex)
        {
            return StatusCode(500, new { error = $"Failed to parse Trivy output: {ex.Message}" });
        }

        if (report?.Results == null)
        {
            return Ok(new { message = "No vulnerabilities found or no results returned.", imageName });
        }

        var scanResult = new ScanResult
        {
            ImageName = imageName,
            ScannedAt = DateTime.UtcNow,
            Vulnerabilities = new List<Vulnerability>()
        };

        foreach (var result in report.Results)
        {
            if (result.Vulnerabilities == null) continue;

            foreach (var vuln in result.Vulnerabilities)
            {
                scanResult.Vulnerabilities.Add(new Vulnerability
                {
                    VulnerabilityId = vuln.VulnerabilityID,
                    PkgName = vuln.PkgName,
                    Severity = vuln.Severity,
                    InstalledVersion = vuln.InstalledVersion,
                    FixedVersion = vuln.FixedVersion
                });
            }
        }

        _context.ScanResults.Add(scanResult);
        await _context.SaveChangesAsync(cancellationToken);

        var summary = scanResult.Vulnerabilities
            .GroupBy(v => v.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() });

        return Ok(new
        {
            scanResult.Id,
            scanResult.ImageName,
            scanResult.ScannedAt,
            TotalVulnerabilities = scanResult.Vulnerabilities.Count,
            SeverityBreakdown = summary
        });
    }

    [HttpGet("history")]
    public async Task<IActionResult> GetHistory()
    {
        var scans = await _context.ScanResults
            .OrderByDescending(s => s.ScannedAt)
            .Select(s => new
            {
                s.Id,
                s.ImageName,
                s.ScannedAt,
                TotalVulnerabilities = s.Vulnerabilities.Count
            })
            .ToListAsync();

        return Ok(scans);
    }

    [HttpGet("dashboard")]
    public async Task<IActionResult> GetDashboard()
    {
        var totalScans = await _context.ScanResults.CountAsync();
        var totalVulnerabilities = await _context.Vulnerabilities.CountAsync();

        var overallSeverityBreakdown = await _context.Vulnerabilities
            .GroupBy(v => v.Severity)
            .Select(g => new { Severity = g.Key, Count = g.Count() })
            .ToListAsync();

        var trend = await _context.ScanResults
            .OrderBy(s => s.ScannedAt)
            .Select(s => new
            {
                s.ImageName,
                s.ScannedAt,
                TotalVulnerabilities = s.Vulnerabilities.Count
            })
            .ToListAsync();

        var topVulnerableImages = await _context.ScanResults
            .GroupBy(s => s.ImageName)
            .Select(g => new
            {
                ImageName = g.Key,
                TotalVulnerabilities = g.SelectMany(s => s.Vulnerabilities).Count(),
                ScanCount = g.Count()
            })
            .OrderByDescending(x => x.TotalVulnerabilities)
            .Take(5)
            .ToListAsync();

        var mostCommonCves = await _context.Vulnerabilities
            .GroupBy(v => v.VulnerabilityId)
            .Select(g => new
            {
                VulnerabilityId = g.Key,
                Count = g.Count(),
                Severity = g.Select(v => v.Severity).FirstOrDefault()
            })
            .OrderByDescending(x => x.Count)
            .Take(10)
            .ToListAsync();

        return Ok(new
        {
            TotalScans = totalScans,
            TotalVulnerabilities = totalVulnerabilities,
            OverallSeverityBreakdown = overallSeverityBreakdown,
            Trend = trend,
            TopVulnerableImages = topVulnerableImages,
            MostCommonCves = mostCommonCves
        });
    }
}
