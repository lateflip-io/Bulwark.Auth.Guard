using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Bulwark.Auth.Guard.Exceptions;
using JWT.Algorithms;
using JWT.Builder;
using RestSharp;

namespace Bulwark.Auth.Guard;

public class Authenticate
{
    private readonly RestClient _client;
    private Dictionary<string, Key> _keys = new();
    private readonly Dictionary<SocialProvider, string> _socialProviders = new()
    {
        { SocialProvider.Google, "google" },
        { SocialProvider.Microsoft, "microsoft" },
        { SocialProvider.Github, "github" }
    };
    
    public Authenticate(string baseUri)
    {
        _client = new RestClient(baseUri);
        _client.AddDefaultHeader("Content-Type", "application/json");
        _client.AddDefaultHeader("Accept", "application/json");
    }
    
    public Authenticate(RestClient client)
    {
        _client = client;
    }
    
    /// <summary>
    /// Authenticates and account using password
    /// </summary>
    /// <param name="email"></param>
    /// <param name="password"></param>
    /// <returns>Authenticated Object</returns>
    /// <exception cref="BulwarkException">400 status can't auth</exception>
    public async Task<Authenticated> Password(string email,
        string password)
    {
        var payload = new
        {
            Email = email,
            Password = password
        };

        var request = new RestRequest("authentication/authenticate")
            .AddJsonBody(payload);

       
        var response = await _client.ExecutePostAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
        if(response.Content != null)
        {
            return JsonSerializer.Deserialize<Authenticated>(response.Content) ?? 
                   throw new BulwarkException("Unknown error");
        }
        
        throw new BulwarkException("Unknown error");
    }
    
    public async Task<Authenticated> MagicCode(string email,
        string code)
    {
        var payload = new
        {
            Email = email,
            Code = code
        };

        var request = new RestRequest("passwordless/magic/authenticate")
            .AddJsonBody(payload);

        var response = await _client.ExecutePostAsync(request);

        if (response.Content != null && (int)response.StatusCode >= 400)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
        }
        
        if(response.Content != null){
            return JsonSerializer.Deserialize<Authenticated>(response.Content) ?? 
                   throw new BulwarkException("No Content");
        }
        
        throw new BulwarkException("Unknown error");
    }
    
    public async Task RequestMagicLink(string email)
    {
        var request = new RestRequest("passwordless/magic/request/{email}")
            .AddUrlSegment("email", email);

        var response = await _client.ExecuteGetAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
    }

    public async Task<Authenticated> Social(SocialProvider provider, string socialToken)
    {
        var payload = new
        {
            Provider = _socialProviders[provider],
            SocialToken = socialToken
        };
        
        var request = new RestRequest("passwordless/social/authenticate")
            .AddJsonBody(payload);
        
        var response = await _client.ExecutePostAsync(request);

        if (response.Content != null && (int)response.StatusCode >= 400)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            } 
        }
        
        if(response.Content != null){
            return JsonSerializer.Deserialize<Authenticated>(response.Content) ?? 
                   throw new BulwarkException("No Content");
        }
        
        throw new BulwarkException("Unknown error");
    }
    
    /// <summary>
    /// When a account is authenticated it will return a accessToken and refreshToken
    /// these need to be acknowledged by the server to be valid and should be done before
    /// using these tokens.
    /// When validating tokens client side the tokens should be still be acknowledged
    /// </summary>
    /// <param name="accessToken"></param>
    /// <param name="refreshToken"></param>
    /// <param name="email"></param>
    /// <param name="deviceId"></param>
    public async Task Acknowledge(string accessToken, string refreshToken,
        string email, string deviceId)
    {
        var payload = new
        {
            Email = email,
            DeviceId = deviceId,
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };

        var request = new RestRequest("authentication/acknowledge")
            .AddJsonBody(payload);


        var response = await _client.ExecutePostAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
    }
    
    /// <summary>
    /// This is a deep validation of an access token. It will check if the token
    /// has been acknowledged, revoked , expired, etc. This is the most secure
    /// check on the token. 
    /// </summary>
    /// <param name="email"></param>
    /// <param name="accessToken"></param>
    /// <param name="deviceId"></param>
    /// <returns></returns>
    /// <exception cref="BulwarkException"></exception>
    public async Task<AccessToken> ValidateAccessToken(string email, string accessToken,
        string deviceId)
    {
        var payload = new
        {
            Email = email,
            Token = accessToken,
            DeviceId = deviceId
        };

        var request = new RestRequest("authentication/accesstoken/validate")
            .AddJsonBody(payload);

        var response = await _client.ExecutePostAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
        
        if(response.Content != null)
        {
            return JsonSerializer.Deserialize<AccessToken>(response.Content) ?? 
                   throw new BulwarkException("No Content");
        }
        
        throw new BulwarkException("Unknown error");
    }
    
    public AccessToken? ValidateAccessTokenClientSide(string accessToken)
    {
        var handler = new JwtSecurityTokenHandler();
        var decodedValue = handler.ReadJwtToken(accessToken);
        var keyId = decodedValue.Header["kid"].ToString() ?? 
                                   throw new BulwarkException("No kid claim");
        Key key;
        
        
        if (_keys.ContainsKey(keyId))
        {
            key = _keys[keyId];
        }
        else
        {
            throw new BulwarkException("Invalid token generation");
        }

        var publicKey = RSA.Create();

        publicKey.ImportFromPem(key.PublicKey.ToCharArray());

        var json = JwtBuilder.Create()
            .WithAlgorithm(new RS256Algorithm(publicKey))
            .MustVerifySignature()
            .Decode(accessToken);
        
        var token = JsonSerializer.Deserialize<AccessToken>(json);

        return token;
    }
    
    public async Task InitializeLocalKeyValidation()
    {
        var request = new RestRequest("keys");
            
        var response = await _client.ExecuteGetAsync(request);

        if (response.Content != null)
        {
            var keys = JsonSerializer.Deserialize<List<Key>>(response.Content);

            if (keys != null)
            {
                _keys = new Dictionary<string, Key>();
                foreach (var key in keys)
                {
                    _keys.Add(key.KeyId, key);
                }
            }
        }
    }
    
    public async Task<Authenticated> Renew(string refreshToken,
        string email, string deviceId)
    {
        var payload = new
        {
            Email = email,
            DeviceId = deviceId,
            Token = refreshToken
        };

        var request = new RestRequest("authentication/renew")
            .AddJsonBody(payload);

        var response = await _client.ExecutePostAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
        if(response.Content != null)
        {
            return JsonSerializer.Deserialize<Authenticated>(response.Content) ?? 
                   throw new BulwarkException("No Content");
        }

        throw new BulwarkException("Unknown error");
    }

    public async Task Revoke(string accessToken,
        string email, string deviceId)
    {
        var payload = new
        {
            Email = email,
            DeviceId = deviceId,
            Token = accessToken
        };

        var request = new RestRequest("authentication/revoke")
            .AddJsonBody(payload);

        var response = await _client.ExecutePostAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
    }
}