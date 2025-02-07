namespace AuthApi.Configuration
{
    public interface IBasicConfig
    {
        public JwtDefaultValues GetJwtDefaultValues();
        CookieOptions GetRefreshCookie();
        CookieOptions GetExpiredRefreshCookie();
    }
}