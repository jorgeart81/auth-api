namespace AuthApi.Configuration
{
    public interface IBasicConfig
    {
        string? JwtKey { get; }
        double JwtExpiration { get; }
        double JwtRefreshExpiration { get; }

        CookieOptions GetRefreshCookie();
        CookieOptions GetExpiredRefreshCookie();
    }
}