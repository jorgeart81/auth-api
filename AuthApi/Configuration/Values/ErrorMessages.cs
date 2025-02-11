using System;

namespace AuthApi.Configuration.Values;

public class ErrorMessages
{
    public const string BAD_CREDENTIALS = "Bad credentials.";
    public const string EMAIL_IS_NOT_VALID = "Email is not valid.";
    public const string ERROR_PROCESSING_REQUEST = "The request could not be processed.";

    public const string UNAUTHORIZED_ACCESS = "Unauthorized access.";
    public const string FORBIDDEN_ACCESS = "Forbidden access.";
    public const string RESOURCE_NOT_FOUND = "The requested resource was not found.";
    public const string METHOD_NOT_ALLOWED = "The HTTP method used is not allowed for this endpoint.";
    public const string UNSUPPORTED_MEDIA_TYPE = "The media type of the request is not supported.";
    public const string REQUEST_TIMEOUT = "The request timed out. Please try again.";

    public const string INVALID_INPUT = "Invalid input provided.";
    public const string MISSING_REQUIRED_FIELDS = "Some required fields are missing.";
    public const string CONFLICT_ERROR = "Conflict detected. The resource may already exist.";
    public const string DUPLICATE_ENTRY = "Duplicate entry detected.";

    public const string SERVER_ERROR = "An unexpected error occurred on the server.";
    public const string SERVICE_UNAVAILABLE = "The service is currently unavailable. Please try again later.";

    public const string TOKEN_EXPIRED = "Token has expired.";
    public const string TOKEN_INVALID = "Invalid token.";
    public const string REFRESH_TOKEN_INVALID = "Invalid or expired refresh token.";

    public const string PASSWORD_TOO_WEAK = "The provided password is too weak.";
    public const string PASSWORD_MISMATCH = "The passwords do not match.";

    public const string ACCOUNT_LOCKED = "The account has been locked due to multiple failed login attempts.";
    public const string ACCOUNT_DISABLED = "The account has been disabled. Please contact support.";

    public const string OPERATION_NOT_ALLOWED = "This operation is not allowed.";
    public const string INSUFFICIENT_PERMISSIONS = "You do not have sufficient permissions to perform this action.";

    public const string RATE_LIMIT_EXCEEDED = "Too many requests. Please slow down.";
    public const string INVALID_FILE_TYPE = "The uploaded file type is not supported.";
    public const string FILE_TOO_LARGE = "The uploaded file exceeds the allowed size.";
}
