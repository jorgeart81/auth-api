using System;
using AuthApi.Data;
using AuthApi.Entities;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
public class Users(ApplicationDbContext context) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<User>>> GetAll()
    {
        var users = await context.Users.ToListAsync();
        return Ok(users.OrderBy(user => user.Id));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<User>> GetById(int id)
    {
        var user = await context.Users.FindAsync(id);
        return Ok(user);
    }

    [HttpPost]
    public async Task<ActionResult> Post(User user)
    {
        context.Users.Add(user);
        await context.SaveChangesAsync();

        return Ok();
    }

    [HttpPut("{id:int}")]
    public async Task<ActionResult<User>> Update(int id, User user)
    {
        if (id != user.Id) return BadRequest("The ids must match");

        context.Update(user);
        await context.SaveChangesAsync();

        return Ok();
    }

    [HttpDelete("{id:int}")]
    public async Task<ActionResult> Delete(int id)
    {
        var recordsDeleted = await context.Users.Where(u => u.Id == id).ExecuteDeleteAsync();

        if (recordsDeleted == 0 ) return NotFound($"User with id ${id} not found");

        return NoContent();
    }

}
