using System;
using System.Collections.Immutable;

namespace AuthApi.ROP.Extensions;

public static partial class Result
{
    public static readonly Unit Unit = Unit.Value;

    public static Result<T> Success<T>(this T value) => new Result<T>(value);

    public static Result<T> Failure<T>(ImmutableArray<string> errors) => new(errors);

    public static Result<T> Failure<T>(string error) => new([error]);

    public static Result<Unit> Success() => new(Unit);

    public static Result<Unit> Failure(ImmutableArray<string> errors) => new(errors);

    public static Result<Unit> Failure(IEnumerable<string> errors) => new(ImmutableArray.Create(errors.ToArray()));

    public static Result<Unit> Failure(string error) => new([error]);
}
