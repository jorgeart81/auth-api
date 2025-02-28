using AuthApi.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public partial class SecureService : ISecureService
{
    private readonly IDataProtector _protector;
    private readonly ITimeLimitedDataProtector _timeLimitedDataProtector;

    private readonly UserManager<IdentityUser> _userManager;
    private const string SECURITY_STAMP = "securityStamp";
    private const string JWT_IS_NULL_ERROR = "JWTKey is null. Please provide a valid JWTKey.";
    private readonly JwtDefaultValues _jwtDefault;

    public SecureService(UserManager<IdentityUser> userManager, IBasicConfig basicConfig, IDataProtectionProvider protectionProvider)
    {
        _userManager = userManager;
        _jwtDefault = new JwtDefaultValues(Key: basicConfig.JwtKey, Expiration: basicConfig.JwtExpiration, RefreshExpiration: basicConfig.JwtRefreshExpiration);
        _protector = protectionProvider.CreateProtector("");
        _timeLimitedDataProtector = _protector.ToTimeLimitedDataProtector();
    }

    public string EncryptForLimitedTime(string text, EncryptLifetime encryptTime)
    {
        long time = (long)encryptTime;
        return _timeLimitedDataProtector.Protect(text, TimeSpan.FromMinutes(time));
    }
    public string DecryptForLimitedTime(string encryptText)
    {
        return _timeLimitedDataProtector.Unprotect(encryptText);
    }
}
