using AuthApi.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

public class ApplicationDbContext : IdentityDbContext
{
    public ApplicationDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<Student> Students { get; set; }
    public DbSet<Quiz> Quizzes { get; set; }
    public DbSet<License> Licenses { get; set; }
    public DbSet<Exam> Exams { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Quiz>()
            .HasIndex(q => q.Title)
            .IsUnique();

        builder.Entity<License>()
            .HasIndex(q => q.LicenseName)
            .IsUnique();

        builder.Entity<Exam>()
            .HasIndex(q => q.ExamName)
            .IsUnique();
    }
}
