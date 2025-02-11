using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class ChangePasswordDTO
{
    [Required]
    public required string CurrentPassword { get; set; }

    [Required]
    public required string NewPassword { get; set; }
}
