using System;
using AuthApi.Entities;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
public class Users
{
    [HttpGet]
    public IEnumerable<User> Get()
    {
        return [
            new() {Id = 1, Name = "Jorge"},
            new() {Id = 2, Name = "Andrés"},
            new() {Id = 2, Name = "Miguel Ángel"},
        ];
    }

}
