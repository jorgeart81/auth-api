using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IJWTService
{
    public Task<(string Token, DateTime Expiration)> GenerateToken(IdentityUser user);
    public Task<(string RefreshToken, DateTime Expiration)> GenerateRefreshToken(IdentityUser user);
}
