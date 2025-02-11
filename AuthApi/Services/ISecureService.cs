using System;

namespace AuthApi.Services;

public interface ISecureService : IJwtService
{
    string DecryptForLimitedTime(string encryptText);
    string EncryptForLimitedTime(string text, EncryptTime encryptTime);
}