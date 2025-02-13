using System.Security.Cryptography;
using System.Text;
using AuthApi.Configuration;
using AuthApi.Configuration.Values;
using AuthApi.Data;
using AuthApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace AuthApi;

public class Startup(IConfiguration configuration)
{
    private readonly string? _dbConnection = configuration.GetValue<string>("DB_CONNECTION_STRING");
    private readonly string _jwtKey = configuration.GetValue<string>("JWT_SECRET_KEY", GenerateRandomKey());

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDataProtection();

        services.AddControllers();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseNpgsql(_dbConnection);
        }
        );

        services.AddIdentityCore<IdentityUser>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

        services.AddScoped<UserManager<IdentityUser>>();
        services.AddScoped<SignInManager<IdentityUser>>();
        services.AddHttpContextAccessor();

        services.AddSingleton<IBasicConfig, BasicConfig>();
        services.AddTransient<ISecureService, SecureService>();
        services.AddTransient<IUserService, UserService>();

        services.AddAuthentication().AddJwtBearer(options =>
        {
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtKey)),
                ClockSkew = TimeSpan.Zero,
            };
        });

        services.AddAuthorization(options =>
        {
            options.AddPolicy(Strings.IS_ADMIN, policy => policy.RequireClaim(Strings.IS_ADMIN));
        });

        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
            {
                Title = "Auth API",
                Description = "This is an api with jwt authentication.",
                Contact = new Microsoft.OpenApi.Models.OpenApiContact
                {
                    Email = "hola@jorgereyesdev.com",
                    Name = "Jorge Reyes",
                    Url = new Uri("https://jorgereyesdev.com"),
                },
                License = new Microsoft.OpenApi.Models.OpenApiLicense
                {
                    Name = "MIT",
                    Url = new Uri("https://opensource.org/license/mit")
                }
            });

            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer",
                BearerFormat = "JWT",
                In = ParameterLocation.Header
            });
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                 Array.Empty<string>()
                }
            });
        });
    }

    public void Configure(IApplicationBuilder app)
    {
        // Middlewares
        app.UseSwagger();
        app.UseSwaggerUI();

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
