using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IJWTService
{
    public Task<(JwtSecurityToken Token, DateTime Expiration)> GenerateToken(IdentityUser user);
}
