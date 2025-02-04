using System;

namespace AuthApi;

public class Startup()
{

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllers();
    }

    public void Configure(IApplicationBuilder app)
    {
        // Middlewares
        app.UseHttpsRedirection();
        app.UseRouting();

        app.UseEndpoints(endpoints => endpoints.MapControllers());

    }
}
