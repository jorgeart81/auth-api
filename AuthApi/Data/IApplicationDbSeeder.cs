using System;

namespace AuthApi.Data;

public interface IApplicationDbSeeder
{
    public Task InitializeDatabaseAsync(CancellationToken cancellationToken);
}
