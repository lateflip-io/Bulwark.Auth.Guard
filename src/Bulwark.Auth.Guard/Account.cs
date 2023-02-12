using System.Text.Json;
using System.Threading.Tasks;
using Bulwark.Auth.Guard.Exceptions;
using RestSharp;

namespace Bulwark.Auth.Guard;
public class Account
{
    private readonly RestClient _client;
    
    public Account(string baseUri)
    {
        _client = new RestClient(baseUri);
        _client.AddDefaultHeader("Content-Type", "application/json");
        _client.AddDefaultHeader("Accept", "application/json");
    }
    
    public Account(RestClient client)
    {
        _client = client;
    }
    
    /// <summary>
    /// Creates an account in bulwark-auth, this will send an email to the account
    /// email for verification
    /// </summary>
    /// <param name="email"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    /// <exception cref="BulwarkException"></exception>
    public async Task Create(string email,
        string password)
    {
        var payload = new
        {
            Email = email,
            Password = password
        };

        var request = new RestRequest("accounts/create")
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
    /// Delete an account on bulwark-auth, the user must be logged in and send
    /// a valid access token to delete the account.
    /// </summary>
    /// <param name="email"></param>
    /// <param name="accessToken"></param>
    /// <returns></returns>
    /// <exception cref="System.Exception"></exception>
    public async Task Delete(string email,
        string accessToken)
    {
        var payload = new
        {
            Email = email,
            AccessToken = accessToken
        };

        var request = new RestRequest("accounts/delete")
            .AddJsonBody(payload);
        var response = await _client.ExecutePutAsync(request);

        if ((int)response.StatusCode >= 400)
        {
            if (response.Content != null)
            {
                var error = JsonSerializer
                    .Deserialize<Error>(response.Content);
                if (error != null && error.Detail != null)
                {
                    throw new BulwarkException(error.Detail);
                }
                
                throw new BulwarkException("Unknown error");
            }
        }
    }
    
    /// <summary>
    /// To verify an account the verification token needs to be verified to activate an account
    /// an account is not usable until it is verified
    /// </summary>
    /// <param name="email"></param>
    /// <param name="verificationToken"></param>
    /// <returns></returns>
    /// <exception cref="System.Exception"></exception>
    public async Task Verify(string email,
        string verificationToken)
    {
        var payload = new
        {
            Email = email,
            Token = verificationToken
        };

        var request = new RestRequest("accounts/verify")
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
    /// This is used to change an email of the account of authenticated
    /// account.
    /// </summary>
    /// <param name="email"></param>
    /// <param name="newEmail"></param>
    /// <param name="accessToken"></param>
    /// <returns></returns>
    /// <exception cref="BulwarkAccountException"></exception>
    public async Task Email(string email,
        string newEmail, string accessToken)
    {
        var payload = new
        {
            Email = email,
            NewEmail = newEmail,
            AccessToken = accessToken
        };

        var request = new RestRequest("accounts/email")
            .AddJsonBody(payload);

        var response = await _client.ExecutePutAsync(request);

        if ((int)response.StatusCode >= 400 && response.Content != null)
        {
            var error = JsonSerializer
                .Deserialize<Error>(response.Content);
            if (error is { Detail: { } })
            {
                throw new BulwarkAccountException(error.Detail);
            }
            
            throw new BulwarkException("Unknown error");
        }
    }
    
    /// <summary>
    /// This is used to change an email of authenticated account
    /// </summary>
    /// <param name="email"></param>
    /// <param name="newPassword"></param>
    /// <param name="accessToken"></param>
    /// <returns></returns>
    /// <exception cref="BulwarkException"></exception>
    public async Task Password(string email,
        string newPassword, string accessToken)
    {
        var payload = new
        {
            Email = email,
            NewPassword = newPassword,
            AccessToken = accessToken
        };

        var request = new RestRequest("accounts/password")
            .AddJsonBody(payload);

        var response = await _client.ExecutePutAsync(request);

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
    /// The email sent out should provide a link to end point that uses
    /// this method to change the password
    /// </summary>
    /// <param name="email"></param>
    /// <param name="newPassword"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    /// <exception cref="BulwarkException"></exception>
    public async Task ForgotPassword(string email,
        string newPassword, string token)
    {
        var payload = new
        {
            Email = email,
            Password = newPassword,
            Token = token
        };

        var request = new RestRequest("accounts/forgot")
            .AddJsonBody(payload);

        var response = await _client.ExecutePutAsync(request);

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
    /// Triggers a forgot password email
    /// </summary>
    /// <param name="email">email of the account to send the email to</param>
    /// <returns></returns>
    /// <exception cref="BulwarkException"></exception>
    public async Task ForgotRequest(string email)
    {
        var request = new RestRequest("accounts/forgot/{email}")
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

    /// <summary>
    /// Checks is account is in the role provided a valid access token needs to be provided
    /// </summary>
    /// <param name="role"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    public bool InRole(string role, AccessToken token)
    {
        return token.Roles.Contains(role.ToLower());
    }

    /// <summary>
    /// Check is an account as the permission provided a valid access token needs to be provided
    /// </summary>
    /// <param name="permission"></param>
    /// <param name="token"></param>
    /// <returns></returns>
    public bool HasPermission(string permission, AccessToken token)
    {
        return token.Permissions.Contains(permission.ToLower());
    }
}