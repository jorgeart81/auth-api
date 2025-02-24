using System;
using System.Runtime.ExceptionServices;
using AuthApi.Models;

namespace AuthApi.Extensions;

public static class ResultBind
{
    public static Result<U> Bind<T, U>(this Result<T> r, Func<T, Result<U>> method)
    {
        try
        {
            return r.Success
                ? method(r.Value)
                : Result.Failure<U>(r.Errors);
        }
        catch (Exception e)
        {
            ExceptionDispatchInfo.Capture(e).Throw();
            throw;
        }
    }

    public static async Task<Result<U>> Bind<T, U>(this Task<Result<T>> result, Func<T, Task<Result<U>>> method)
    {
        try
        {
            var r = await result;
            return r.Success
                ? await method(r.Value)
                : Result.Failure<U>(r.Errors);
        }
        catch (Exception e)
        {
            ExceptionDispatchInfo.Capture(e).Throw();
            throw;
        }
    }
}
