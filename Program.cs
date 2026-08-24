using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = "RuthBookAppSuperSecretKey123456789";

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngular", policy =>
    {
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors("AllowAngular");

app.UseAuthentication();
app.UseAuthorization();

var books = new List<Book>
{
    new Book
    {
        Id = 1,
        Title = "Harry Potter",
        Author = "J.K. Rowling",
        PublicationDate = "1997-06-26"
    }
};

var users = new List<User>();

app.MapPost("/api/register", (User user) =>
{
    if (users.Any(u => u.Username == user.Username))
    {
        return Results.BadRequest("Username already exists.");
    }

    users.Add(user);

    return Results.Ok(new
    {
        message = "Registration successful"
    });
});

app.MapPost("/api/login", (User loginUser) =>
{
    var user = users.FirstOrDefault(u =>
        u.Username == loginUser.Username &&
        u.Password == loginUser.Password);

    if (user == null)
    {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username)
    };

    var key = new SymmetricSecurityKey(
        Encoding.UTF8.GetBytes(jwtKey));

    var credentials = new SigningCredentials(
        key,
        SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddHours(2),
        signingCredentials: credentials);

    var tokenString =
        new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new
    {
        token = tokenString
    });
});

app.MapGet("/api/books", () =>
{
    return Results.Ok(books);
})
.RequireAuthorization();

app.MapPost("/api/books", (Book book) =>
{
    book.Id = books.Count == 0
        ? 1
        : books.Max(b => b.Id) + 1;

    books.Add(book);

    return Results.Ok(book);
})
.RequireAuthorization();

app.MapPut("/api/books/{id}", (int id, Book updatedBook) =>
{
    var book = books.FirstOrDefault(b => b.Id == id);

    if (book == null)
    {
        return Results.NotFound();
    }

    book.Title = updatedBook.Title;
    book.Author = updatedBook.Author;
    book.PublicationDate = updatedBook.PublicationDate;

    return Results.Ok(book);
})
.RequireAuthorization();

app.MapDelete("/api/books/{id}", (int id) =>
{
    var book = books.FirstOrDefault(b => b.Id == id);

    if (book == null)
    {
        return Results.NotFound();
    }

    books.Remove(book);

    return Results.NoContent();
})
.RequireAuthorization();

app.Run();

class Book
{
    public int Id { get; set; }
    public string Title { get; set; } = "";
    public string Author { get; set; } = "";
    public string PublicationDate { get; set; } = "";
}

class User
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
}