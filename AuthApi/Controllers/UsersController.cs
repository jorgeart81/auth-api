using System.Security.Claims;
using AuthApi.DTOs;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IConfiguration configuration, IJwtService jWTService) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> Register(UserCredentialsDTO credentialsDTO)
    {
        if (credentialsDTO.Password == null) return IncorrectReturn("Incorrect register");

        var user = new IdentityUser
        {
            UserName = credentialsDTO.Email,
            Email = credentialsDTO.Email,
        };
        var result = await userManager.CreateAsync(user, credentialsDTO.Password);

        if (result.Succeeded)
        {
            return await BuildToken(user.Email);
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
        var errorMessage = "Incorrect login";
        if (credentialsDTO.Password == null) return IncorrectReturn(errorMessage);

        var user = await userManager.FindByEmailAsync(credentialsDTO.Email);

        if (user is null || string.IsNullOrEmpty(user.Email)) return IncorrectReturn(errorMessage);

        var result = await signInManager.CheckPasswordSignInAsync(user, credentialsDTO.Password, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            return await BuildToken(user.Email);
        }
        else
        {
            return IncorrectReturn(errorMessage);
        }
    }

    [HttpGet("refresh-token")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken)) return IncorrectReturn("Bad request.");

        var claims = jWTService.GetClaims(refreshToken);
        var email = claims.FindFirstValue(ClaimTypes.Email);

        if (string.IsNullOrEmpty(email)) return IncorrectReturn("Bad request.");

        var user = await userManager.FindByEmailAsync(email);

        if (user?.Email is null) return Unauthorized();

        return await BuildToken(email: user.Email, cookieToken: refreshToken);
    }


    private ActionResult IncorrectReturn(string message)
    {
        ModelState.AddModelError(string.Empty, message);
        return ValidationProblem();
    }

    private async Task<AuthenticationResponseDTO> BuildToken(string email, double minutes = 10080, string? cookieToken = null)
    {
        var user = await userManager.FindByEmailAsync(email);

        if (user == null) return new AuthenticationResponseDTO() { Token = null };

        var (token, expiration) = await jWTService.GenerateToken(user);

        if (string.IsNullOrWhiteSpace(cookieToken))
        {
            var (refreshToken, _) = await jWTService.GenerateRefreshToken(user);
            cookieToken = refreshToken;
        }

        Response.Cookies.Append("refreshToken", cookieToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(7) //TODO -> equal to the expiration value of the jwtRefresh
        });

        return new AuthenticationResponseDTO()
        {
            Token = token,
            Expiration = expiration
        };
    }

}
