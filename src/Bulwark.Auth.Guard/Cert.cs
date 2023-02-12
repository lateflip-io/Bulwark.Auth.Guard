using System.Text.Json.Serialization;

namespace Bulwark.Auth.Guard;

public class Cert
{
    [JsonPropertyName("generation")]
    public int Generation { get; set; }
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; }

    public Cert()
    {
        PublicKey = string.Empty;
    }
}