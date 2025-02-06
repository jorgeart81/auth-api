using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

public class JwtService(IConfiguration configuration, UserManager<IdentityUser> userManager) : IJwtService
{
    private readonly string? jwtKey = configuration["Jwt:Key"];
    private readonly double jwtExpiration = Convert.ToDouble(configuration["Jwt:Expiration"]);
    private readonly double jwtRefreshExpiration = Convert.ToDouble(configuration["Jwt:RefreshExpiration"]);

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

    public ClaimsPrincipal GetClaims(string token)
    {
        if (jwtKey is null) throw new Exception("JWTKey is null. Please provide a valid JWTKey.");

        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew = TimeSpan.Zero,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            return principal;
        }
        catch (SecurityTokenException ex)
        {
            throw new Exception("Invalid token.", ex);
        }
        catch (Exception ex)
        {
            throw new Exception("Error validating token.", ex);
        }
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