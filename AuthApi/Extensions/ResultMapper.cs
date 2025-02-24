using System;
using System.Runtime.ExceptionServices;
using AuthApi.Models;

namespace AuthApi.Extensions;

public static class ResultMapper
{
    public static Result<U> Map<T, U>(this Result<T> r, Func<T, U> mapper)
    {
        try
        {
            return r.Success
                ? Result.Success(mapper(r.Value))
                : Result.Failure<U>(r.Errors);
        }
        catch (Exception e)
        {
            ExceptionDispatchInfo.Capture(e).Throw();
            throw;
        }
    }
}
