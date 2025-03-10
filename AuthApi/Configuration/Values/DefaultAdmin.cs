using System;

namespace AuthApi.Configuration.Values;

public class DefaultAdmin
{
    public required string DefaultUsername { get; set; }
    public required string DefaultPassword { get; set; }
}
