using System.Text.Json.Serialization;

namespace Bulwark.Auth.Client;

public class AccessToken
{
    [JsonPropertyName("jti")] public string Jti { get; set; }
    [JsonPropertyName("iss")] public string Iss { get; set; }
    [JsonPropertyName("aud")] public string Aud { get; set; }
    [JsonPropertyName("roles")] public List<string> Roles { get; set; }
    [JsonPropertyName("permissions")] public List<string> Permissions { get; set; }
    [JsonPropertyName("exp")] public int Exp { get; set; }
    [JsonPropertyName("sub")] public string Sub { get; set; }
    public AccessToken(){
        Roles = new List<string>();
        Permissions = new List<string>();
        Jti = string.Empty;
        Iss = string.Empty;
        Aud = string.Empty;
        Exp = 0;
        Sub = string.Empty;
    }
}
  

   
