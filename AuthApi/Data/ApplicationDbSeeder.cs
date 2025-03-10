using System.Security.Claims;
using AuthApi.Configuration.Values;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

public class ApplicationDbSeeder(UserManager<IdentityUser> userManager, ApplicationDbContext applicationDbContext, IConfiguration config) : IApplicationDbSeeder
{
    public readonly UserManager<IdentityUser> _userManager = userManager;
    private readonly ApplicationDbContext _applicationDbContext = applicationDbContext;
    private readonly IConfiguration _config = config;

    public async Task InitializeDatabaseAsync(CancellationToken cancellationToken = default)
    {
        if (_applicationDbContext.Database.GetMigrations().Any())
        {
            if ((await _applicationDbContext.Database.GetPendingMigrationsAsync(cancellationToken)).Any())
            {
                await _applicationDbContext.Database.MigrateAsync(cancellationToken);
            }

            if (await _applicationDbContext.Database.CanConnectAsync(cancellationToken))
            {
                await InitializeAdminUserAsync();
            }
        }
    }

    private async Task InitializeAdminUserAsync()
    {
        var defaultAdmin = _config.GetSection(nameof(DefaultAdmin)).Get<DefaultAdmin>();

        if (string.IsNullOrEmpty(defaultAdmin?.DefaultUsername)) return;

        IdentityUser? userInDb = await _userManager.FindByEmailAsync(defaultAdmin.DefaultUsername);

        if (userInDb is not null) { return; }

        if (await _userManager.Users
            .FirstOrDefaultAsync(user => user.Email == defaultAdmin.DefaultUsername)
            is not IdentityUser incomingUser)
        {
            incomingUser = new IdentityUser
            {
                UserName = defaultAdmin.DefaultUsername,
                Email = defaultAdmin.DefaultUsername,
                EmailConfirmed = true,
                PhoneNumberConfirmed = true,
                NormalizedEmail = defaultAdmin.DefaultUsername.ToUpperInvariant(),
                NormalizedUserName = defaultAdmin.DefaultUsername.ToUpperInvariant(),
            };

            var passwordHash = new PasswordHasher<IdentityUser>();

            incomingUser.PasswordHash = passwordHash.HashPassword(incomingUser, defaultAdmin.DefaultPassword);
            var identityResult = await _userManager.CreateAsync(incomingUser);

            if (identityResult.Succeeded)
            {
                userInDb = await _userManager.FindByEmailAsync(defaultAdmin.DefaultUsername);
                if (userInDb is not null) await _userManager.AddClaimAsync(userInDb, new Claim(Strings.IS_ADMIN, "true"));
            }
        }
    }
}


