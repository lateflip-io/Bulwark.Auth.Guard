using System.Threading.Tasks;
using RestSharp;

namespace Bulwark.Auth.Guard;

public class Guard
{
    private readonly RestClient _client;
    public Account Account { get; }
    public Authenticate Authenticate { get; }

    public Guard(string baseUri)
    {
        _client = new RestClient(baseUri);
        _client.AddDefaultHeader("Content-Type", "application/json");
        _client.AddDefaultHeader("Accept", "application/json");
        Account = new Account(_client);
        Authenticate = new Authenticate(_client);
    }
    
    /// <summary>
    /// simple method to ping the server if it is up.
    /// </summary>
    /// <returns></returns>
    public async Task<bool> IsHealthy()
    {
        var request = new RestRequest("health");
        var response = await _client.ExecuteGetAsync(request);

        return ((int)response.StatusCode) == 200;
    }
}



