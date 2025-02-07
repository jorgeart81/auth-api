using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

public class EditClaimDTO
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
}
