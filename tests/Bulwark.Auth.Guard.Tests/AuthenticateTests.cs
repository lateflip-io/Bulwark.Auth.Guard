using Bulwark.Auth.Guard.Exceptions;

namespace Bulwark.Auth.Guard.Tests;

public class AuthenticateTests
{
    private readonly Guard _guard = new("http://localhost:8080");
    private readonly string _testEmail = $"test_{Guid.NewGuid()}@lateflip.io";
    private readonly string _testPassword = $"{Guid.NewGuid().ToString()}1!S";
    private readonly MailhogClient _mailHog = new(
        new Uri("http://localhost:8025"));

    [Fact]
    public async Task AuthenticatePassword()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
    }
    
    [Fact]
    public async Task AuthenticatePasswordWithWrongPassword()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
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
    public async Task AuthenticatePasswordAndAcknowledgeValidateLocal()
    {
        await _guard.Authenticate.InitializeLocalKeyValidation();
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        Assert.NotNull(authenticated.RefreshToken);

        await _guard.Authenticate.Acknowledge(authenticated.AccessToken,
            authenticated.RefreshToken, _testEmail,
            Guid.NewGuid().ToString());

        var token =
            _guard.Authenticate.ValidateAccessTokenClientSide(authenticated.AccessToken);
        Assert.NotNull(token);
    }
    [Fact]
    public async Task AuthenticatePasswordAndAcknowledgeValidate()
    {
        var deviceId = Guid.NewGuid().ToString();
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        Assert.NotNull(authenticated.RefreshToken);

        await _guard.Authenticate.Acknowledge(authenticated.AccessToken,
            authenticated.RefreshToken, _testEmail,
            deviceId);

        var token = await _guard.Authenticate.ValidateAccessToken(_testEmail,
            authenticated.AccessToken, deviceId);
        Assert.NotNull(token);
    }
    [Fact]
    public async Task AuthenticatePasswordValidate()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        Assert.NotNull(authenticated.RefreshToken);

        try
        {
            await _guard.Authenticate.ValidateAccessToken(_testEmail,
                authenticated.AccessToken, "deviceId");
            Assert.Fail("Should not be able to validate.No Acknowledgement");
        }
        catch(BulwarkException exception)
        {
            Assert.True(true, exception.Message);
        }
    }
    
    [Fact]
    public async Task RenewAuthentication()
    {
        var deviceId = Guid.NewGuid().ToString();
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        Assert.NotNull(authenticated.RefreshToken);
        await _guard.Authenticate.Acknowledge(authenticated.AccessToken,
            authenticated.RefreshToken, _testEmail,
            deviceId);
        try
        {
            await _guard.Authenticate.ValidateAccessToken(_testEmail,
                authenticated.AccessToken, "deviceId");
            Assert.Fail("Should not be able to validate. No Acknowledgement");
        }
        catch (BulwarkException exception)
        {
            Assert.True(true, exception.Message);
        }

        authenticated = await _guard.Authenticate.Renew(authenticated.RefreshToken, _testEmail,
            deviceId);

        Assert.NotNull(authenticated.RefreshToken);
    }
    
    [Fact]
    public async Task RevokeAuthentication()
    {
        var deviceId = Guid.NewGuid().ToString();
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        var authenticated = await _guard.Authenticate.Password(_testEmail,
            _testPassword);
        Assert.NotNull(authenticated.AccessToken);
        Assert.NotNull(authenticated.RefreshToken);
        await _guard.Authenticate.Acknowledge(authenticated.AccessToken,
            authenticated.RefreshToken, _testEmail,
            deviceId);
        await _guard.Authenticate.Revoke(authenticated.AccessToken, _testEmail,
            deviceId);
        
        try
        {
            await _guard.Authenticate.ValidateAccessToken(_testEmail,
                authenticated.AccessToken, "deviceId");
            Assert.Fail("Should not be able to validate. Revoked");
        }
        catch (BulwarkException exception)
        {
            Assert.True(true, exception.Message);
        }
    }
    
    [Fact]
    public async Task RequestMagicLinkAndAuthenticate()
    {
        await _guard.Account.Create(_testEmail, _testPassword);
        var messages = await _mailHog.GetMessagesAsync();
        var message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        await _mailHog.DeleteAsync(message.ID);
        await _guard.Account.Verify(_testEmail, message.Subject);
        await _guard.Authenticate.RequestMagicLink(_testEmail);
        messages = await _mailHog.GetMessagesAsync();
        message = messages.Items
            .FirstOrDefault(m => m.To[0].Address == _testEmail);
        Assert.NotNull(message);
        Assert.NotNull(message.Subject);
        var authenticated = await _guard.Authenticate.MagicCode(_testEmail,
            message.Subject);
        Assert.NotNull(authenticated.AccessToken);
        
        await _mailHog.DeleteAsync(message.ID);
    }
    
    [Fact]
    public async Task GoogleLoginAndAuthenticate()
    {
        var googleToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI3NDA1MmEyYjY0NDg3NDU3NjRlNzJjMzU5MDk3MWQ5MGNmYjU4NWEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJuYmYiOjE2NzUwMjk5NzcsImF1ZCI6IjY1MTg4MjExMTU0OC0waHJnN2U0bzkwcTFpdXRtZm4wMnFrZjltOTBrM2QzZy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEwMjIzODE1MDc1NDU1ODI4NTM3MyIsImhkIjoibGF0ZWZsaXAuaW8iLCJlbWFpbCI6ImZyaXR6QGxhdGVmbGlwLmlvIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF6cCI6IjY1MTg4MjExMTU0OC0waHJnN2U0bzkwcTFpdXRtZm4wMnFrZjltOTBrM2QzZy5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsIm5hbWUiOiJGcmVkcmljayBTZWl0eiIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BRWRGVHA3RThDUVJUVUZUNUJabEtJVTVjY2hmdFBMSDJ5eU0zN2dKaWVBRT1zOTYtYyIsImdpdmVuX25hbWUiOiJGcmVkcmljayIsImZhbWlseV9uYW1lIjoiU2VpdHoiLCJpYXQiOjE2NzUwMzAyNzcsImV4cCI6MTY3NTAzMzg3NywianRpIjoiN2IzMWY5ZDlmMTNmZmE4MWU1ZDJmODg3M2Q5MmE4YjFjYzMwYTY4YSJ9.SsYhaisQRBnYzCy6YWAy3Lo1unWOGC3BRPZswd4TuJFhgZUcUROVK_3FOGpnn1RXTPac3yX-0QnAj-LUpXgsP-in4DYm0hxvlkRGCyg9EmfY7S_W-LX4Jmuhy2bHlYdb2PDmxrd-1p77IhjYaXj5_Eagqf5rLxo6E0bEJSJAp0xcrE1zRx-SN3xMfLIIirzn-zAujcsTOtAady_jKxrLuMs-JXIf5K71ZC7EJhmoM0pp8Wq0AqfMCWhRZ4ElDD7c2MGB5by3S_dmu1kP2R6O2qPzPtHEumgdGE0MV3W2gcqjqQIVK-1HaMoUbl0c4e4agIuWI-evg3Qc7IJlWOsMFQ";
        try
        {
            var authenticated = await _guard.Authenticate.Social(SocialProvider.Google, googleToken);
            Assert.NotNull(authenticated.AccessToken);
        }
        catch(Exception exception)
        {
            Assert.Contains("token cannot be validated", exception.Message);
        }
    }
}