using System.Text.Json.Serialization;

namespace Bulwark.Auth.Client;

public class Authenticated
{
    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; }
    [JsonPropertyName("refreshToken")]
    public string RefreshToken { get; set; }

    public Authenticated() {
        AccessToken = string.Empty;
        RefreshToken = string.Empty;
    }
}