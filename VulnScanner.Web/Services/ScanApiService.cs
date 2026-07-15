using System.Net.Http.Json;

namespace VulnScanner.Web.Services;

public class ScanResultDto
{
    public int Id { get; set; }
    public string ImageName { get; set; } = string.Empty;
    public DateTime ScannedAt { get; set; }
    public int TotalVulnerabilities { get; set; }
    public List<SeverityCountDto>? SeverityBreakdown { get; set; }
}

public class SeverityCountDto
{
    public string Severity { get; set; } = string.Empty;
    public int Count { get; set; }
}

public class TrendPointDto
{
    public string ImageName { get; set; } = string.Empty;
    public DateTime ScannedAt { get; set; }
    public int TotalVulnerabilities { get; set; }
}

public class TopImageDto
{
    public string ImageName { get; set; } = string.Empty;
    public int TotalVulnerabilities { get; set; }
    public int ScanCount { get; set; }
}

public class CommonCveDto
{
    public string VulnerabilityId { get; set; } = string.Empty;
    public int Count { get; set; }
    public string Severity { get; set; } = string.Empty;
}

public class DashboardDto
{
    public int TotalScans { get; set; }
    public int TotalVulnerabilities { get; set; }
    public List<SeverityCountDto>? OverallSeverityBreakdown { get; set; }
    public List<TrendPointDto>? Trend { get; set; }
    public List<TopImageDto>? TopVulnerableImages { get; set; }
    public List<CommonCveDto>? MostCommonCves { get; set; }
}

public class ScanApiService
{
    private readonly HttpClient _http;

    public ScanApiService(HttpClient http)
    {
        _http = http;
    }

    public async Task<ScanResultDto?> ScanImageAsync(string imageName)
    {
        return await _http.GetFromJsonAsync<ScanResultDto>($"api/scan/{imageName}");
    }

    public async Task<List<ScanResultDto>?> GetHistoryAsync()
    {
        return await _http.GetFromJsonAsync<List<ScanResultDto>>("api/scan/history");
    }

    public async Task<DashboardDto?> GetDashboardAsync()
    {
        return await _http.GetFromJsonAsync<DashboardDto>("api/scan/dashboard");
    }
}
