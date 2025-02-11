using System.Security.Claims;
using AuthApi.Configuration;
using AuthApi.Configuration.Values;
using AuthApi.DTOs;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, ISecureService secureService, IBasicConfig basicConfig, IUserService userService) : ControllerBase
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

        if (result.Succeeded) return await BuildAuthenticationResponse(user.Email);

        else
        {
            var errorsDescription = result.Errors.Select(e => e.Description).ToArray();
            return IncorrectReturn(errorsDescription);
        }
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> Login(UserCredentialsDTO credentialsDTO)
    {
        var errorMessage = "Incorrect login";

        var user = await userManager.FindByEmailAsync(credentialsDTO.Email);

        if (string.IsNullOrEmpty(user?.Email)) return IncorrectReturn([errorMessage]);

        var result = await signInManager.CheckPasswordSignInAsync(user, credentialsDTO.Password, lockoutOnFailure: false);

        if (result.Succeeded)
        {
            return await BuildAuthenticationResponse(user.Email);
        }
        else
        {
            return IncorrectReturn([errorMessage]);
        }
    }

    [HttpGet("refresh-token")]
    [AllowAnonymous]
    public async Task<ActionResult<AuthenticationResponseDTO>> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken)) return IncorrectReturn(["Bad request."]);

        var email = await secureService.GetEmailFromToken(refreshToken);
        if (string.IsNullOrEmpty(email)) return IncorrectReturn(["Bad request."]);

        return await BuildAuthenticationResponse(email: email, cookieToken: refreshToken);
    }

    [HttpPost("make-admin", Name = "makeAdmin")]
    // [Authorize(Policy = Strings.isAdmin)]
    public async Task<ActionResult> MakeAdmin(EditClaimDTO editClaimDTO)
    {
        var user = await userManager.FindByEmailAsync(editClaimDTO.Email);
        if (user == null) return BadRequest("The request could not be processed");

        await userManager.AddClaimAsync(user, new Claim(Strings.isAdmin, "true"));
        return NoContent();
    }

    [HttpPost("remove-admin", Name = "removeAdmin")]
    public async Task<ActionResult> RemoveAdmin(EditClaimDTO editClaimDTO)
    {
        var user = await userManager.FindByEmailAsync(editClaimDTO.Email);
        if (user == null) return BadRequest("The request could not be processed");

        await userManager.RemoveClaimAsync(user, new Claim(Strings.isAdmin, "true"));
        return NoContent();
    }

    [HttpGet("logout", Name = "logout")]
    public async Task<ActionResult> Logout()
    {
        var user = await userService.GetLoginUser();
        if (user == null) return BadRequest("The request could not be processed");

        SetRefreshCookie(Response, basicConfig.GetExpiredRefreshCookie(), "");
        return Ok(new { message = "Logged out successfully." });
    }


    [HttpPost("change-password")]
    public async Task<ActionResult> ChangePassword(ChangePasswordDTO changePasswordDTO)
    {
        var errorMessage = "The request could not be processed";
        var loginUser = await userService.GetLoginUser();

        if (string.IsNullOrEmpty(loginUser?.Email)) return IncorrectReturn([errorMessage]);

        var result = await userManager.ChangePasswordAsync(loginUser, changePasswordDTO.CurrentPassword, changePasswordDTO.NewPassword);

        if (result.Succeeded)
        {
            await Logout();
            return Ok(new { message = "Password changed successfully, logged out." });
        }
        else
        {
            return IncorrectReturn([errorMessage]);
        }
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDTO forgotPasswordDTO)
    {
        var user = await userManager.FindByEmailAsync(forgotPasswordDTO.Email);
        if (user?.Email == null) return BadRequest("Invalid email.");

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = $"{forgotPasswordDTO.FrontendUrl}?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email)}";

        //TODO - Simulation: send by email (in production, use an email service)
        return Ok(new { message = "Password reset link generated.", resetLink });
    }

    [HttpPost("reset-password", Name = "resetPassword")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordDTO resettPasswordDTO)
    {
        var user = await userManager.FindByEmailAsync(resettPasswordDTO.Email);
        if (user == null) return BadRequest("Invalid request.");

        var result = await userManager.ResetPasswordAsync(user, resettPasswordDTO.Token, resettPasswordDTO.NewPassword);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(new { message = "Password reset successfully" });
    }

    private ActionResult IncorrectReturn(string[] errorsDescription)
    {
        foreach (var error in errorsDescription)
        {
            ModelState.AddModelError(string.Empty, error);
        }
        return ValidationProblem();
    }

    private async Task<AuthenticationResponseDTO> BuildAuthenticationResponse(string email, string? cookieToken = null)
    {
        var user = await userManager.FindByEmailAsync(email);

        if (user == null) return new AuthenticationResponseDTO() { Token = null };

        var (token, expiration) = await secureService.GenerateToken(user);

        if (string.IsNullOrWhiteSpace(cookieToken)) await BuildRefreshCookie(user);

        return new AuthenticationResponseDTO()
        {
            Token = token,
            Expiration = expiration
        };
    }

    private async Task BuildRefreshCookie(IdentityUser user)
    {
        var (refreshToken, _) = await secureService.GenerateRefreshToken(user);

        SetRefreshCookie(Response, basicConfig.GetRefreshCookie(), refreshToken);
    }

    readonly Action<HttpResponse, CookieOptions, string> SetRefreshCookie = (response, cookieOptions, token) =>
    {
        response.Cookies.Append("refreshToken", token, cookieOptions);
    };
}
