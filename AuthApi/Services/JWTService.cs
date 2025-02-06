using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

public class JWTService(IConfiguration configuration, UserManager<IdentityUser> userManager) : IJWTService
{
    private readonly string? jwtKey = configuration["JWTKey"];
    private const double jwtExpiration = 30; // minutes
    private const double jwtRefreshExpiration = 10080; // 7 days

    public async Task<(string Token, DateTime Expiration)> GenerateToken(IdentityUser user)
    {
        var buildToken = await BuildToken(user, jwtExpiration);

        return buildToken;
    }

    public async Task<(string RefreshToken, DateTime Expiration)> GenerateRefreshToken(IdentityUser user)
    {
        var buildToken = await BuildToken(user, jwtRefreshExpiration);

        return buildToken;
    }

    private async Task<(string Token, DateTime Expiration)> BuildToken(IdentityUser user, double minutes)
    {
        if (jwtKey is null) throw new Exception("JWTKey is null. Please provide a valid JWT key.");

        if (user.Email is null || user.SecurityStamp is null) throw new Exception("User is null.");

        var claims = new List<Claim>()
        {
            new Claim("email", user.Email),
            new Claim("securityStamp", user.SecurityStamp)
        };

        var claimsDb = await userManager.GetClaimsAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var notBefore = DateTime.UtcNow;
        var expiration = DateTime.UtcNow.AddMinutes(minutes);

        claims.AddRange(claimsDb);

        var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims, notBefore: notBefore, expires: expiration, signingCredentials: creds);

        return (new JwtSecurityTokenHandler().WriteToken(securityToken), expiration);
    }
}