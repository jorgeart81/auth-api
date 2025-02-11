namespace AuthApi.Configuration;

public sealed class BasicConfig(IConfiguration configuration) : IBasicConfig
{
    private readonly string? _jwtKey = configuration["Jwt:Key"];
    private readonly double _jwtExpiration = Convert.ToDouble(configuration["Jwt:Expiration"]);
    private readonly double _jwtRefreshExpiration = Convert.ToDouble(configuration["Jwt:RefreshExpiration"]);

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
