namespace AuthApi.Configuration;

public sealed class BasicConfig(IConfiguration configuration) : IBasicConfig
{
    public string? JwtKey => configuration.GetValue<string>("JWT_SECRET_KEY");

    public double JwtExpiration => Convert.ToDouble(configuration.GetValue<double>("Jwt:Expiration", 30)); // minutes

    public double JwtRefreshExpiration => Convert.ToDouble(configuration.GetValue<double>("Jwt:RefreshExpiration", 10080)); // minutes

    public CookieOptions GetRefreshCookie()
    {
        var expirationTime = TimeSpan.FromMinutes(JwtRefreshExpiration);
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.Add(expirationTime),
            MaxAge = expirationTime,
        };
    }

    public CookieOptions GetExpiredRefreshCookie()
    {
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTime.UtcNow.AddDays(-1),
            MaxAge = TimeSpan.Zero,
        };
    }
}
