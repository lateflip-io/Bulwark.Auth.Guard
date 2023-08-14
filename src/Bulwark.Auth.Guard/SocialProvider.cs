namespace Bulwark.Auth.Guard;
/// <summary>
/// This is a enum of the social providers that are supported by Bulwark.Auth
/// </summary>
public enum SocialProvider
{
    //when adding enums please up date authenticate.cs to support the new provider
    Google,
    Microsoft,
    Github
}