using System;
using System.Runtime.ExceptionServices;
using AuthApi.Models;

namespace AuthApi.Extensions;

public static class ResultThen
{
    public static Result<T> Then<T>(this Result<T> r, Action<T> action)
    {
        try
        {
            if (r.Success)
            {
                action(r.Value);
            }

            return r;
        }
        catch (Exception e)
        {
            ExceptionDispatchInfo.Capture(e).Throw();
            throw;
        }
    }
}