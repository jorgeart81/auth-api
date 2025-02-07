using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IJwtService
{
    Task<(string Token, DateTime Expiration)> GenerateToken(IdentityUser user);
    Task<(string RefreshToken, DateTime Expiration)> GenerateRefreshToken(IdentityUser user);
    Task<string> GetEmailFromToken(string token);
    ClaimsPrincipal GetClaims(string token);
}
