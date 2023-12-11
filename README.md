# Bulwark.Auth.Guard (BETA)

Is a client .net library for `Bulwark.Auth` which is a JWT based api developer focused auth subsystem.
Please see: https://github.com/lateflip-io/Bulwark.Auth

# Contributing
- Each contribution will need a issue/ticket created to track the feature or bug fix before it will be considered
- The PR must pass all tests and be reviewed by an official maintainer
- Each PR must be linked to an issue/ticket, once the PR is merged the ticket will be auto closed
- Each feature/bugfix needs to have unit tests
- Each feature must have the code documented inline

There is a docker compose file in the root of the project that `must` be used to run the tests.
This can be started by running `docker-compose up` in the root of the project.
Mocks are not used in `Guard` tests, `Bulwark.Auth` must be running and in test mode. Test mode just allows easy 
extraction of tokens from emails sent out. This is all handled by starting the services with 
docker compose.

The Reason mocks are not used in most cases is good to verify the integration with `Bulwark.Auth` is working
with the latest version. It removes the false sense of security that comes with mocking. 

## Usage

Add the package to your project:
https://www.nuget.org/packages/Bulwark.Auth.Guard

`Bulwark.Auth` must be setup and running and should be accessible via a public url or 
internal network.
    
```csharp
// Create a new instance of the client
var guard  = new Guard("http://localhost:8080");
if(guard.IsHealty())
{
    Console.WriteLine("Bulwark.Auth is up and running");
}
else
{
    Console.WriteLine("Bulwark.Auth is not running");
}
```

`Guard` is currently used for two major areas of functionality: 

## Account management and administration summary 

It allows a users to create an account and manager their account such as changing 
passwords, email address. These can only be changed if a users account is verified and 
a user has a valid JWT token.

Creating an account can be done in traditional way by creating a username (email only supported)
and password. This will trigger an email to be sent to the user with a verification link.

The other way is to login with a Social Sign-In, after the user has authenticated
with google, microsoft, or github; submitting the Id Token/access token from the provider to `Bulwark.Auth`
will validate it against the provider and create an account for the user. This will also link 
an account with same email if already exists. When logging in with a Social Sign-In, if `Bulwark.Auth` creates
an account it does not need to be verified and will be automatically verified.

Sign up with username and password does require verification from the email used. 

## Authentication and Acknowledgement summary

Once an account is created and verified a user can login.
There are a few ways to login, classic username and password, magic code (Bulwark.Auth will send out an email), and social sign-in.
On successful login a payload will be returned with a JWT access token and refresh token.
To use enable the use of the access token and the refresh token it must be acknowledged with a device id.
The device Id is left up to client application to generate, but useful for supporting multiple devices.
Once acknowledged the access token can be validated to access protected resources.

The access token is short lived token when it expires a longer lived refresh token can be used
to get a new access token. If the refresh token is expired the user should be logged out 
of the client application and forced to login again.

If a users account was created by a Social Sign-In the user will not have a password, however if the user 
wants to login with a password the forgot password flow can be used to create a password for the user.

## JWT Token Validation
Once a authenticated payload is acknowledged a access token can be validated server side. 
It is good to validated access tokens periodically to ensure they are still valid and haven't been tampered
with. Server side validation will check for revocation, expiration, and more.
        
```csharp
try
{
    var jwtInfo = await guard.Authenticate.ValidateAccessToken("test@latflip.io",
        authenticated.AccessToken, "deviceId");
}
catch(BulwarkException exception)
{
    // The token is invalid
}

```

The `Guard` client can be used to validate access tokens without server side validation. This is useful
for client side validation to reduce round trips to the server. But you don't get deep validation if
a token has been revoked or an account disabled. You will need to initialize
local validation which will cache the public signing key.


```csharp
// Initializing local validation only needs to be done once per lifetime of the client
guard.Authenticate.InitializeLocalKeyValidation();

var jwtInfo =
    guard.Authenticate.ValidateAccessTokenClientSide(authenticated.AccessToken);

```

Client validation does not require a token to be acknowledged, but it is recommended to acknowledge
a token in case you need to revoke it and need server side validation. Client side validation
will only validate expiration and signature. Also you cannot refresh an access token without acknowledging.



