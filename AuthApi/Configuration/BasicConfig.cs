namespace AuthApi.Configuration;

public sealed class BasicConfig(IConfiguration configuration) : IBasicConfig
{
    private readonly string? _jwtKey = configuration.GetValue<string>("JWT_SECRET_KEY");
    private readonly double _jwtExpiration = Convert.ToDouble(configuration.GetValue<double>("Jwt:Expiration", 30)); // minutes
    private readonly double _jwtRefreshExpiration = Convert.ToDouble(configuration.GetValue<double>("Jwt:RefreshExpiration", 10080)); // minutes

    public JwtDefaultValues GetJwtDefaultValues()
    {
        return new JwtDefaultValues(Key: _jwtKey, Expiration: _jwtExpiration, RefreshExpiration: _jwtRefreshExpiration);
    }

    public CookieOptions GetRefreshCookie()
    {
        var expirationTime = TimeSpan.FromMinutes(_jwtRefreshExpiration);
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
