using AuthApi.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public partial class SecureService : ISecureService
{
    private readonly IDataProtector _protector;
    private readonly ITimeLimitedDataProtector _timeLimitedDataProtector;
    private readonly JwtDefaultValues _jwtDefault;
    private readonly UserManager<IdentityUser> _userManager;
    private const string SECURITY_STAMP = "securityStamp";
    private const string JWT_IS_NULL_ERROR = "JWTKey is null. Please provide a valid JWTKey.";

    public SecureService(UserManager<IdentityUser> userManager, IBasicConfig basicConfig, IDataProtectionProvider protectionProvider)
    {
        _userManager = userManager;
        _jwtDefault = basicConfig.GetJwtDefaultValues();
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
