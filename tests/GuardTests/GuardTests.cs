namespace GuardTests;
public class GuardBulwarkClientTests
{
    private readonly Guard _guard;
    public GuardBulwarkClientTests()
    {
        //https://localhost:44332
        _guard = new Guard("http://localhost:7988");
    }

    [Fact]
    public async void Healthy()
    {
        var health = await _guard.IsHealthy();
        Assert.True(health);
    }
}
