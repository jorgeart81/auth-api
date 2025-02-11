using System;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IUserService
{
    Task<IdentityUser?> GetLoginUser();
}
