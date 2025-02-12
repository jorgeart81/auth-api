namespace AuthApi.Models;

public class Result<T>(T value, bool isSuccess = default, string? error = null)
{
    public T Value { get; } = value;
    public bool IsSucess { get; } = isSuccess;
    public string? Error { get; } = error;

    public static Result<T> Success(T value) => new Result<T>(value, true, null);
    public static Result<T> Failure(string error) => new Result<T>(default, false, error);
}
