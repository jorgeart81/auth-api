using System;
using System.Collections.Immutable;
using AuthApi.ROP;

namespace AuthApi.Models;

public static partial class ApiResponse
{
    public static ApiResponse<T> Success<T>(this T data) => new ApiResponse<T>(data);
    public static ApiResponse<T> Success<T>(this T data, string message) => new ApiResponse<T>(data, message);
    public static ApiResponse<Unit> Failure(string message) => new ApiResponse<Unit>(message);
    public static ApiResponse<Unit> Failure(ImmutableArray<ErrorDetail> errors, string? message = null)
    {
        if (errors.Length == 0)
        {
            throw new InvalidOperationException("You should specify at least one error.");
        }

        var errorDetails = SetErrors(errors);
        return new ApiResponse<Unit>(errorDetails, message);
    }

    private static Dictionary<string, ImmutableArray<string>> SetErrors(ImmutableArray<ErrorDetail> errors) =>
        errors.GroupBy(e => e.Field)
              .ToDictionary(g => g.Key, g => g.Select(e => e.Message).ToImmutableArray());

}
