using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

public partial class SecureService : IJwtService
{
    public async Task<(string Token, DateTime Expiration)> GenerateToken(IdentityUser user)
    {
        var buildToken = await BuildToken(user, _jwtDefault.Expiration);

        return buildToken;
    }

    public async Task<(string RefreshToken, DateTime Expiration)> GenerateRefreshToken(IdentityUser user)
    {
        var buildToken = await BuildToken(user, _jwtDefault.RefreshExpiration);

        return buildToken;
    }

    public async Task<string> GetEmailFromToken(string token)
    {
        var claims = GetClaims(token);
        var emailClaims = claims.FindFirstValue(ClaimTypes.Email);
        var securityStampClaims = claims.FindFirstValue(SECURITY_STAMP);

        if (string.IsNullOrWhiteSpace(emailClaims) || string.IsNullOrWhiteSpace(securityStampClaims)) throw new Exception("Invalid token.");

        var isValidSecurityStamp = await ValidateSecurityStamp(emailClaims, securityStampClaims);

        if (!isValidSecurityStamp) throw new Exception("Invalid token.");

        return emailClaims;
    }

    public ClaimsPrincipal GetClaims(string token)
    {
        if (_jwtDefault.Key is null) throw new Exception(JWT_IS_NULL_ERROR);

        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtDefault.Key)),
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

    private async Task<bool> ValidateSecurityStamp(string emailClaims, string securityStampClaims)
    {
        var user = await _userManager.FindByEmailAsync(emailClaims);

        if (user is null) return false;

        return user.SecurityStamp == securityStampClaims;
    }

    private async Task<(string Token, DateTime Expiration)> BuildToken(IdentityUser user, double minutes)
    {
        if (_jwtDefault.Key is null) throw new Exception(JWT_IS_NULL_ERROR);

        if (user.Email is null || user.SecurityStamp is null) throw new Exception("User is null.");

        var claims = new List<Claim>()
        {
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(SECURITY_STAMP, user.SecurityStamp)
        };

        var claimsDb = await _userManager.GetClaimsAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtDefault.Key));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiration = DateTime.UtcNow.AddMinutes(minutes);

        claims.AddRange(claimsDb);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiration,
            SigningCredentials = creds,
        };

        var handler = new JwtSecurityTokenHandler();
        var securityToken = handler.CreateToken(tokenDescriptor);

        return (new JwtSecurityTokenHandler().WriteToken(securityToken), expiration);
    }
}
