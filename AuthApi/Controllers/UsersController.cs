using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthApi.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager, IConfiguration configuration) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> Register(UserCredentialsDTO credentialsDTO)
    {
        var user = new IdentityUser
        {
            UserName = credentialsDTO.Email,
            Email = credentialsDTO.Email,
        };

        var result = await userManager.CreateAsync(user, credentialsDTO.Password);

        if (result.Succeeded)
        {
            return await BuildToken(credentialsDTO);
        }
        else
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return ValidationProblem();
        }

    }

    private async Task<AuthenticationResponseDTO> BuildToken(UserCredentialsDTO userCredentials, double minutes = 10080)
    {
        var jwtKey = configuration["JWTKey"];
        if (jwtKey == null) return new AuthenticationResponseDTO() { Token = null };

        var user = await userManager.FindByEmailAsync(userCredentials.Email);
        if (user == null) return new AuthenticationResponseDTO() { Token = null };

        var claims = new List<Claim>()
        {
            new Claim("email", userCredentials.Email)
        };
        var claimsDb = await userManager.GetClaimsAsync(user);
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiration = DateTime.UtcNow.AddMinutes(minutes);

        claims.AddRange(claimsDb);

        var securityToken = new JwtSecurityToken(issuer: null, audience: null, claims: claims, expires: expiration, signingCredentials: creds);

        return new AuthenticationResponseDTO()
        {
            Token = new JwtSecurityTokenHandler().WriteToken(securityToken),
            Expiration = expiration
        };
    }

}
