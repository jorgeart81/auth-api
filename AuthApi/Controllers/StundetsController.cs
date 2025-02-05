using System;
using AuthApi.Data;
using AuthApi.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/users")]
[Authorize]
public class Students(ApplicationDbContext context) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<Student>>> GetAll()
    {
        var students = await context.Students.ToListAsync();
        return Ok(students.OrderBy(user => user.Id));
    }

    [HttpGet("{id:int}")]
    public async Task<ActionResult<Student>> GetById(int id)
    {
        var student = await context.Students.FindAsync(id);
        return Ok(student);
    }

    [HttpPost]
    public async Task<ActionResult> Post(Student student)
    {
        context.Add(student);
        await context.SaveChangesAsync();

        return Ok();
    }

    [HttpPut("{id:int}")]
    public async Task<ActionResult<Student>> Update(int id, Student student)
    {
        if (id != student.Id) return BadRequest("The ids must match");

        context.Update(student);
        await context.SaveChangesAsync();

        return Ok();
    }

    [HttpDelete("{id:int}")]
    public async Task<ActionResult> Delete(int id)
    {
        var recordsDeleted = await context.Students.Where(x => x.Id == id).ExecuteDeleteAsync();

        if (recordsDeleted == 0) return NotFound($"User with id ${id} not found");

        return NoContent();
    }

}
