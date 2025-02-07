namespace AuthApi.Configuration
{
    public sealed record JwtDefaultValues(string? Key, double Expiration, double RefreshExpiration) { }

}
