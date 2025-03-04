using System;
using System.ComponentModel.DataAnnotations;

namespace AuthApi.Entities;

public class License
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MinLength(2), MaxLength(100)]
    public required string LicenseName { get; set; }

    public int ExamId { get; set; }
    public Exam? Exam { get; set; }
    public List<Quiz> Quizzes { get; set; } = [];
}
