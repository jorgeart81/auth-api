using System;

namespace AuthApi.Services;

public interface ISecureService : IJwtService
{
    string DecryptForLimitedTime(string encryptText);
    string EncryptForLimitedTime(string text, EncryptLifetime encryptTime);
}

public enum EncryptLifetime
{
    OneMinute = 1,
    FiveMinutes = 5,
    TenMinutes = 10,
}