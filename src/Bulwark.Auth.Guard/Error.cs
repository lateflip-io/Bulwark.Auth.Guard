using System.Text.Json.Serialization;

namespace Bulwark.Auth.Guard;

public class Error
{
	[JsonPropertyName("title")]
	public string Title { get; set; }
	[JsonPropertyName("detail")]
	public string Detail { get; set; }
	[JsonPropertyName("type")]
	public string Type { get; set; }
	[JsonPropertyName("statusCode")]
	public string StatusCode { get; set; }
                   
	public Error()
	{
		Title = string.Empty;
		Detail = string.Empty;
		Type = string.Empty;
		StatusCode = string.Empty;
	}
}