using AuthApi.Data;

namespace AuthApi;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var startup = new Startup(builder.Configuration);

        startup.ConfigureServices(builder.Services);

        var app = builder.Build();

        await startup.AddInitializeDatabaseAsync(app.Services, app.Lifetime.ApplicationStopping);
        startup.Configure(app);

        app.Run();
    }
}
