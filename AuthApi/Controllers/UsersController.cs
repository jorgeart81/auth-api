using System.Security.Claims;
using AuthApi.Configuration;
using AuthApi.Configuration.Values;
using AuthApi.DTOs;
using AuthApi.Models;
using AuthApi.ROP;
using AuthApi.ROP.Extensions;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class UsersController(UserManager<IdentityUser> userManager,
SignInManager<IdentityUser> signInManager, ISecureService secureService,
 IBasicConfig basicConfig, IUserService userService) : ControllerBase
{
    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<ActionResult> Register(UserCredentialsDTO credentialsDTO)
    {
        var user = new IdentityUser
        {
            UserName = credentialsDTO.Email,
            Email = credentialsDTO.Email,
        };

        var userResult = await GetUserByEmailAsync(credentialsDTO.Email);
        if (userResult.Success)
        {
            if (userResult.Value.Email == credentialsDTO.Email)
                return BadRequest(ApiResponse<AuthenticationResponseDTO>.Failure([new ErrorDetail { Field = "email", Message = $"Unable to register email {credentialsDTO.Email}." }]));
        }

        var result = await userManager.CreateAsync(user, credentialsDTO.Password);
        if (result.Succeeded)
            return Created();

        else
        {
            var errorsDescription = result.Errors.Select(e =>
                new ErrorDetail { Field = e.Code, Message = e.Description }).ToList();

            return BadRequest(ApiResponse<AuthenticationResponseDTO>.Failure(errors: errorsDescription));
        }
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<ActionResult> Login(UserCredentialsDTO credentialsDTO)
    {
        var userResult = await GetUserByEmailAsync(credentialsDTO.Email);
        if (!userResult.Success)
            return Unauthorized(ApiResponse<AuthenticationResponseDTO>.Failure(message: ErrorMessages.BAD_CREDENTIALS));

        var user = userResult.Value;
        var checkPassword = await signInManager.CheckPasswordSignInAsync(user, credentialsDTO.Password, lockoutOnFailure: false);

        if (checkPassword.Succeeded)
            return Ok(ApiResponse<AuthenticationResponseDTO>.Success(await BuildAuthenticationResponse(user.Email!)));

        else
            return Unauthorized(ApiResponse<AuthenticationResponseDTO>.Failure(message: ErrorMessages.BAD_CREDENTIALS));
    }

    [HttpGet("refresh-token")]
    [AllowAnonymous]
    public async Task<ActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken)) return BadRequest();

        var email = await secureService.GetEmailFromToken(refreshToken);
        if (string.IsNullOrEmpty(email)) return BadRequest();

        return Ok(ApiResponse<AuthenticationResponseDTO>.Success(await BuildAuthenticationResponse(email: email, cookieToken: refreshToken)));

    }

    [HttpPost("make-admin", Name = "makeAdmin")]
    // [Authorize(Policy = Strings.isAdmin)]
    public async Task<ActionResult> MakeAdmin(EditClaimDTO editClaimDTO)
    {
        var userResult = await GetUserByEmailAsync(editClaimDTO.Email);
        if (!userResult.Success)
            return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.ERROR_PROCESSING_REQUEST));

        await userManager.AddClaimAsync(userResult.Value, new Claim(Strings.IS_ADMIN, "true"));
        return NoContent();
    }

    [HttpPost("remove-admin", Name = "removeAdmin")]
    public async Task<ActionResult> RemoveAdmin(EditClaimDTO editClaimDTO)
    {
        var userResult = await GetUserByEmailAsync(editClaimDTO.Email);
        if (!userResult.Success)
            return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.ERROR_PROCESSING_REQUEST));

        await userManager.RemoveClaimAsync(userResult.Value, new Claim(Strings.IS_ADMIN, "true"));
        return NoContent();
    }

    [HttpGet("logout", Name = "logout")]
    public async Task<ActionResult> Logout()
    {
        var user = await userService.GetLoginUser();
        if (user == null) return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.ERROR_PROCESSING_REQUEST));

        SetRefreshCookie(Response, basicConfig.GetExpiredRefreshCookie(), "");
        return Ok(ApiResponse<string>.Success(message: "Logged out successfully."));
    }


    [HttpPost("change-password")]
    public async Task<ActionResult> ChangePassword(ChangePasswordDTO changePasswordDTO)
    {
        var loginUser = await userService.GetLoginUser();
        if (string.IsNullOrEmpty(loginUser?.Email) || string.IsNullOrEmpty(loginUser?.PasswordHash)) return IncorrectReturn([new ErrorModel { Key = string.Empty, Description = ErrorMessages.ERROR_PROCESSING_REQUEST }]);

        var passwordHasher = new PasswordHasher<IdentityUser>();
        var verifyResult = passwordHasher.VerifyHashedPassword(loginUser, loginUser.PasswordHash, changePasswordDTO.NewPassword);
        if (verifyResult == PasswordVerificationResult.Success)
            return BadRequest(ApiResponse<AuthenticationResponseDTO>.Failure([new ErrorDetail { Field = "password", Message = ErrorMessages.PASSWORD_CHANGE_FAILED }]));


        var result = await userManager.ChangePasswordAsync(loginUser, changePasswordDTO.CurrentPassword, changePasswordDTO.NewPassword);
        if (result.Succeeded)
        {
            await Logout();
            return Ok(ApiResponse<string>.Success(message: "Password changed successfully, logged out."));
        }
        else
        {
            return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.ERROR_PROCESSING_REQUEST));
        }
    }

    [HttpPost("forgot-password")]
    [AllowAnonymous]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDTO forgotPasswordDTO)
    {
        var userResult = await GetUserByEmailAsync(forgotPasswordDTO.Email);
        if (!userResult.Success)
            return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.EMAIL_IS_NOT_VALID));

        var user = userResult.Value;
        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = $"{forgotPasswordDTO.FrontendUrl}?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(forgotPasswordDTO.Email)}";

        //TODO - Simulation: send by email (in production, use an email service)
        return Ok(new { message = "Password reset link generated.", resetLink });
    }

    [HttpPost("reset-password", Name = "resetPassword")]
    [AllowAnonymous]
    public async Task<IActionResult> ResetPassword(ResetPasswordDTO resettPasswordDTO)
    {
        var userResult = await GetUserByEmailAsync(resettPasswordDTO.Email);
        if (!userResult.Success)
            return BadRequest(ApiResponse<string>.Failure(message: ErrorMessages.EMAIL_IS_NOT_VALID));

        var user = userResult.Value;
        var result = await userManager.ResetPasswordAsync(user, resettPasswordDTO.Token, resettPasswordDTO.NewPassword);
        if (!result.Succeeded) return BadRequest(result.Errors);

        return Ok(ApiResponse<string>.Success(message: "Password reset successfully."));
    }

    private async Task<Result<IdentityUser>> GetUserByEmailAsync(string email)
    {
        var user = await userManager.FindByEmailAsync(email);

        if (user is null) return Result.Failure<IdentityUser>("User not found.");
        if (user.Email is null) return Result.Failure<IdentityUser>("User email not found.");

        return user;
    }

    private ActionResult IncorrectReturn(ErrorModel[] errors)
    {
        foreach (var error in errors)
        {
            ModelState.AddModelError(error.Key, error.Description);
        }
        return ValidationProblem();
    }

    private async Task<AuthenticationResponseDTO> BuildAuthenticationResponse(string email, string? cookieToken = null)
    {
        var user = await userManager.FindByEmailAsync(email);
        if (user is null) return new AuthenticationResponseDTO() { Token = null };

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
