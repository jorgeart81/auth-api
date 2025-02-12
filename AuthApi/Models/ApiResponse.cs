using System.Text.Json.Serialization;

namespace AuthApi.Models;

public class ApiResponse<T>
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Message { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public T? Data { get; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Dictionary<string, List<string>>? Errors { get; }

    private ApiResponse(string? message, T? data, List<ErrorDetail>? errors = null)
    {
        Message = message;
        Data = data;
        Errors = errors != null ? SetErrors(errors) : null;
    }

    public static ApiResponse<T> Success(T data = default, string? message = null) =>
        new ApiResponse<T>(message: message, data: data, errors: null);

    public static ApiResponse<T> Failure(List<ErrorDetail>? errors = null, string? message = null) =>
        new ApiResponse<T>(message: message, data: default, errors: errors);

    private readonly Func<List<ErrorDetail>, Dictionary<string, List<string>>> SetErrors = (errors) =>
         errors.GroupBy(e => e.Field)
               .ToDictionary(g => g.Key, g => g.Select(e => e.Message).ToList());

}

public class ErrorDetail
{
    public required string Field { get; set; }
    public required string Message { get; set; }
}

