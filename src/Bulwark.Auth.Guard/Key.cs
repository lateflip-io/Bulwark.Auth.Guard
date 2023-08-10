using System;
using System.Text.Json.Serialization;

namespace Bulwark.Auth.Guard;

/// <summary>
/// "keyId": "6d9f6ec7-ca08-48d6-b783-059b43ef12d9",
/// "format": "PKCS#1",
/// "publicKey": "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAzbh/4VW0pvatNbno8t+JGylmfq3ZotMspetDyg0ikVAOPypqnEtRpIfc+ugZ3udU\r\nwIpDBdTXziwAmL/v0r4l0areOHzVmTZgFHcN+rdTrzcn2kO7bafWgvsHpQROeq/4H6r6pzSnj/5B\r\nTohKPLdRohDbONzdaDx3m2NOt2cyUrmCOJKxY59Fv/dPzm692vRy3BveKsOeiua2kV/LH5X7dBrS\r\nIENxVmd5oaWUEJ3s/2DZnLPwFvGB7U1vLmeGF8yLJFrOP/Q/SThUtUiQYQZ9s1Cog1btbOyWB29E\r\nB8dYXEh5bCkv+Z2u5TnblSxhT54fIFKMKFhInk/HHhb0+6psiQIDAQAB\n-----END RSA PUBLIC KEY-----",
/// "algorithm": "RS256",
/// "created": "2023-08-01T22:59:27.989Z"
/// </summary>
public class Key
{
    [JsonPropertyName("keyId")]
    public string KeyId { get; set; }
    [JsonPropertyName("format")]
    public string Format { get; set; }
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; }
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; }
    [JsonPropertyName("created")]
    public DateTime Created { get; set; }
}