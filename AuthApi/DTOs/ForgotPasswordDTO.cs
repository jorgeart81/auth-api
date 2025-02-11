using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class ForgotPasswordDTO
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }

    [Required]
    public required string FrontendUrl { get; set; }

}
