using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;

namespace AuthApi.Services;

public class UserService(UserManager<IdentityUser> userManager, IHttpContextAccessor contextAccessor) : IUserService
{

	public async Task<IdentityUser?> GetLoginUser()
	{
		var emailClaim = contextAccessor?.HttpContext?.User.Claims.Where(x => x.Type == JwtRegisteredClaimNames.Email).FirstOrDefault();

		if (emailClaim is null) return null;

		var email = emailClaim.Value;

		return await userManager.FindByEmailAsync(email);
	}
}
