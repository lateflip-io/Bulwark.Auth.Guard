namespace Bulwark.Auth.Guard.Tests;
public class GuardBulwarkClientTests
{
    private readonly Guard _guard = new("http://localhost:8080");
    //https://localhost:44332

    [Fact]
    public async void Healthy()
    {
        var health = await _guard.IsHealthy();
        Assert.True(health);
    }
}
