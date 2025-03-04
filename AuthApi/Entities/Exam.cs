using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Entities;

public class Exam
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MinLength(2), MaxLength(100)]
    public required string ExamName { get; set; }

    public List<License> Licenses { get; set; } = [];
}
