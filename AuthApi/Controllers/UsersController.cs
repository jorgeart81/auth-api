using System.IdentityModel.Tokens.Jwt;
using AuthApi.DTOs;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration, IJWTService jWTService) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> Register(UserCredentialsDTO credentialsDTO)
    {
        if (credentialsDTO.Password == null) return IncorrectLoginReturn();

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

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> Login(UserCredentialsDTO credentialsDTO)
    {
        if (credentialsDTO.Password == null) return IncorrectLoginReturn();

        var user = await userManager.FindByEmailAsync(credentialsDTO.Email);

        if (user is null) return IncorrectLoginReturn();

        var result = await signInManager.CheckPasswordSignInAsync(user, credentialsDTO.Password, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            return await BuildToken(credentialsDTO);
        }
        else
        {
            return IncorrectLoginReturn();
        }
    }

    private ActionResult IncorrectLoginReturn()
    {
        ModelState.AddModelError(string.Empty, "Incorrect login");
        return ValidationProblem();
    }

    private async Task<AuthenticationResponseDTO> BuildToken(UserCredentialsDTO userCredentials, double minutes = 10080)
    {
        var user = await userManager.FindByEmailAsync(userCredentials.Email);

        if (user == null) return new AuthenticationResponseDTO() { Token = null };

        var (token, expiration) = await jWTService.GenerateToken(user);
        var (refreshToken, _) = await jWTService.GenerateRefreshToken(user);

        Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(7)
        });

        return new AuthenticationResponseDTO()
        {
            Token = token,
            Expiration = expiration
        };
    }

}
