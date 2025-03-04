using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Entities;

public class Quiz
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MinLength(5), MaxLength(50)]
    public required string Title { get; set; }

    [MaxLength(255)]
    public string? Description { get; set; }
    public DateTime PublishedAt { get; set; }

    public int LicenseId { get; set; }
    public License? License { get; set; }
}
