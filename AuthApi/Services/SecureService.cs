using AuthApi.Configuration;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public partial class SecureService : ISecureService
{
    private readonly IDataProtector protector;
    private readonly ITimeLimitedDataProtector timeLimitedDataProtector;
    private readonly JwtDefaultValues jwtDefault;
    private readonly UserManager<IdentityUser> userManager;
    private const string SECURITY_STAMP = "securityStamp";
    private const string JWT_IS_NULL_ERROR = "JWTKey is null. Please provide a valid JWTKey.";

    public SecureService(UserManager<IdentityUser> userManager, IBasicConfig basicConfig, IDataProtectionProvider protectionProvider)
    {
        this.userManager = userManager;
        jwtDefault = basicConfig.GetJwtDefaultValues();
        protector = protectionProvider.CreateProtector("");
        timeLimitedDataProtector = protector.ToTimeLimitedDataProtector();
    }

    public string EncryptForLimitedTime(string text, EncryptLifetime encryptTime)
    {
        long time = (long)encryptTime;
        return timeLimitedDataProtector.Protect(text, TimeSpan.FromMinutes(time));
    }
    public string DecryptForLimitedTime(string encryptText)
    {
        return timeLimitedDataProtector.Unprotect(encryptText);
    }
}
