using System;
using AuthApi.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Data;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; }
}
