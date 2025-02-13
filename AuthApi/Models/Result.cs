namespace AuthApi.Models;

public class Result<T>
{
    public T Value { get; }
    public bool IsSucess { get; }
    public string? Error { get; }

    private Result(T value, bool isSuccess = default, string? error = null)
    {
        Value = value;
        IsSucess = isSuccess;
        Error = error;
    }

    public static Result<T> Success(T value) => new Result<T>(value, true, null);
    public static Result<T> Failure(string error) => new Result<T>(default, false, error);
}
