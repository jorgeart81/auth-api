using System;

namespace AuthApi.ROP;

public sealed class Unit
{
    public static readonly Unit Value = new Unit();
    private Unit() { }
}