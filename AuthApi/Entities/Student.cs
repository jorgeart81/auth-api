using System.ComponentModel.DataAnnotations;

namespace AuthApi.Entities;

public class Student
{
    public int Id { get; set; }

    [Required]
    public required string Name { get; set; }
}
