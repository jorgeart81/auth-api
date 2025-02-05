using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

public class JWTService(IConfiguration configuration, UserManager<IdentityUser> userManager) : IJWTService
{
    private readonly string? jwtKey = configuration["JWTKey"];
    private const double jwtExpiration = 10080;

    public async Task<(JwtSecurityToken Token, DateTime Expiration)> GenerateToken(IdentityUser user)
    {
        var buildToken = await BuildToken(user, jwtExpiration);

        return buildToken;
    }

    private async Task<(JwtSecurityToken Token, DateTime Expiration)> BuildToken(IdentityUser user, double minutes)
    {
        if (jwtKey is null) throw new Exception("JWTKey is null. Please provide a valid JWT key.");

        if (user.Email is null) throw new Exception("User is null.");

        var claims = new List<Claim>()
        {
            new Claim("email", user.Email)
        };

        var claimsDb = await userManager.GetClaimsAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiration = DateTime.UtcNow.AddMinutes(minutes);

        claims.AddRange(claimsDb);

        var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims, expires: expiration, signingCredentials: creds);

        return (securityToken, expiration);
    }
}