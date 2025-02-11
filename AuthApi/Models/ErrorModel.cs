using System;

namespace AuthApi.Models;

internal struct ErrorModel
{
    public string Key { get; set; }
    public string Description { get; set; }
}