using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public class UserService(UserManager<IdentityUser> userManager, IHttpContextAccessor contextAccessor) : IUserService
{

	public async Task<IdentityUser?> GetLoginUser()
	{
		var emailClaim = contextAccessor?.HttpContext?.User.Claims.Where(x => x.Type == ClaimTypes.Email).FirstOrDefault();

		if (emailClaim is null) return null;

		var email = emailClaim.Value;

		return await userManager.FindByEmailAsync(email);
	}
}
