using System.Security.Cryptography;
using System.Text;
using AuthApi.Data;
using AuthApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi;

public class Startup(IConfiguration configuration)
{
    private readonly string? defaultConnection = configuration.GetConnectionString("DefaultConnection");
    private readonly string jwtKey = configuration["JWTKey"] ?? GenerateRandomKey();

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (defaultConnection != null) options.UseNpgsql(defaultConnection);
        }
        );

        services.AddIdentityCore<IdentityUser>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

        services.AddScoped<UserManager<IdentityUser>>();
        services.AddScoped<SignInManager<IdentityUser>>();
        services.AddHttpContextAccessor();

        services.AddTransient<IJwtService, JwtService>();

        services.AddAuthentication().AddJwtBearer(options =>
        {
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                ClockSkew = TimeSpan.Zero,
            };
        });
    }

    public void Configure(IApplicationBuilder app)
    {
        // Middlewares
        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseAuthorization();
        app.UseEndpoints(endpoints => endpoints.MapControllers());

    }

    private static string GenerateRandomKey()
    {
        // Generate a cryptographically secure random key (e.g., 32 bytes)
        var bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes);
    }
}
