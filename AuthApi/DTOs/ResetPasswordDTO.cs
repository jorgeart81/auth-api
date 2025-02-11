using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class ResetPasswordDTO
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string NewPassword { get; set; }

    [Required]
    public required string Token { get; set; }

}
