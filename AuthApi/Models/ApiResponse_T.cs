using System.Collections.Immutable;
using System.Text.Json.Serialization;

namespace AuthApi.Models;

public struct ApiResponse<T>
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public T? Data { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, ImmutableArray<string>>? Errors { get; }

    public ApiResponse(T data, string message)
    {
        Message = message;
        Data = data;
        Errors = null;
    }
    public ApiResponse(T data)
    {
        Message = null;
        Data = data;
        Errors = null;
    }

    public ApiResponse(string message)
    {
        Message = message;
        Data = default;
        Errors = null;
    }

    public ApiResponse(Dictionary<string, ImmutableArray<string>> errors, string? message)
    {
        Message = message;
        Data = default;
        Errors = errors;
    }

    private readonly Func<ImmutableArray<ErrorDetail>, Dictionary<string, ImmutableArray<string>>> SetErrors = (errors) =>
         errors.GroupBy(e => e.Field)
               .ToDictionary(g => g.Key, g => g.Select(e => e.Message).ToImmutableArray());
}

public class ErrorDetail
{
    public required string Field { get; set; }
    public required string Message { get; set; }
}

