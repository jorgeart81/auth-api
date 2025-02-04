using System;
using AuthApi.Data;
using Microsoft.EntityFrameworkCore;

namespace AuthApi;

public class Startup(IConfiguration configuration)
{
    private string? defaultConnection = configuration.GetConnectionString("DefaultConnection");
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();

        services.AddDbContext<ApplicationDbContext>(options =>
        {
            if (defaultConnection != null) options.UseNpgsql(defaultConnection);
        }
        );
    }

    public void Configure(IApplicationBuilder app)
    {
        // Middlewares
        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseEndpoints(endpoints => endpoints.MapControllers());

    }
}
