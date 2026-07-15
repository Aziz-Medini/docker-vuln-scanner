using System.Text.Json.Serialization;

namespace VulnScanner.Api.Models;

public class TrivyReport
{
  [JsonPropertyName("Results")]
  public List<TrivyResult>? Results { get; set; }
}

public class TrivyResult
{
  [JsonPropertyName("Target")]
  public string? Target { get; set; }

  [JsonPropertyName("Vulnerabilities")]
  public List<TrivyVulnerability>? Vulnerabilities { get; set; }
}

public class TrivyVulnerability
{
  [JsonPropertyName("VulnerabilityID")]
  public string VulnerabilityID { get; set; } = string.Empty;

  [JsonPropertyName("PkgName")]
  public string PkgName { get; set; } = string.Empty;

  [JsonPropertyName("Severity")]
  public string Severity { get; set; } = string.Empty;

  [JsonPropertyName("InstalledVersion")]
  public string InstalledVersion { get; set; } = string.Empty;

  [JsonPropertyName("FixedVersion")]
  public string? FixedVersion { get; set; }
}
