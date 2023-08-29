using Bulwark.Auth.Guard.Exceptions;

namespace Bulwark.Auth.Guard.Tests;

public class AccountTest
{
    private readonly Guard _guard = new("http://localhost:8080");
    private readonly string _testEmail = $"test_{Guid.NewGuid()}@lateflip.io";
    private readonly string _testPassword = $"{Guid.NewGuid().ToString()}1!S";
    private readonly MailhogClient _mailHog = new(
        new Uri("http://localhost:8025"));

    [Fact]
    public async void CreateVerifyBulwarkAccount()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _guard.Account.Verify(_testEmail, message.Subject);
    }
    
    [Fact]
    public async void CreateDeleteBulwarkAccount()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        await _guard.Account.Delete(_testEmail, authenticated.AccessToken);

        try
        {
            await _guard.Authenticate.Password(_testEmail,
                "wrongpassword");
            Assert.Fail("Should throw a bad request");
        }
        catch (BulwarkException exception)
        {
            Assert.True(true, exception.Message);
        }
    }
    
    [Fact]
    public async void ForgotPassword()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        await _guard.Account.ForgotRequest(_testEmail);
        messages = await _mailHog.GetMessagesAsync();
        message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _guard.Account.ForgotPassword(_testEmail, "new-password1!S",
            message.Subject);
        await _mailHog.DeleteAsync(message.ID);
    }
    
    [Fact]
    public async void ChangePassword()
    {
        var newPassword = "new-password1!S";
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        await _guard.Account.Password(_testEmail, newPassword,
            authenticated.AccessToken);
        authenticated = await _guard.Authenticate.Password(_testEmail,
            newPassword);
        Assert.NotNull(authenticated.AccessToken);
    }
    
    [Fact]
    public async void ChangeEmail()
    {
        var newEmail = $"{Guid.NewGuid()}@lateflip.io";
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        await _guard.Account.Email(_testEmail, newEmail,
            authenticated.AccessToken);
        messages = await _mailHog.GetMessagesAsync();
        //must verify account again with new email
        message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == newEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(newEmail, message.Subject);
        
        authenticated = await _guard.Authenticate.Password(newEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
    }
    
    [Fact]
    public async void ChangeEmailInUse()
    {
        var newEmail = "samezies" + Guid.NewGuid() + "@latflip.io";
        await _guard.Account.Create(_testEmail, _testPassword);
        await _guard.Account.Create(newEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        try
        {
            await _guard.Account.Email(_testEmail, newEmail,
                authenticated.AccessToken);
            Assert.Fail("Should fail change email");
        }
        catch (BulwarkAccountException exception)
        {
            Assert.True(true, exception.Message);
        }
    }
}