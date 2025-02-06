using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IJwtService
{
    public Task<(string Token, DateTime Expiration)> GenerateToken(IdentityUser user);
    public Task<(string RefreshToken, DateTime Expiration)> GenerateRefreshToken(IdentityUser user);
    public ClaimsPrincipal GetClaims(string token);
}
