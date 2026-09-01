using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
    ?? throw new InvalidOperationException(
        "JWT_KEY environment variable is not configured.");

var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? throw new InvalidOperationException(
        "DATABASE_URL environment variable is not configured.");

var databaseUri = new Uri(databaseUrl);

var userInfo = databaseUri.UserInfo.Split(':', 2);

var connectionStringBuilder = new NpgsqlConnectionStringBuilder
{
    Host = databaseUri.Host,
    Port = databaseUri.Port > 0 ? databaseUri.Port : 5432,
    Username = Uri.UnescapeDataString(userInfo[0]),
    Password = userInfo.Length > 1
        ? Uri.UnescapeDataString(userInfo[1])
        : "",
    Database = databaseUri.AbsolutePath.TrimStart('/')
};

var connectionString = connectionStringBuilder.ConnectionString;

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngular", policy =>
    {
        policy.AllowAnyOrigin()
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

/*
 * Create the users table automatically if it does not exist.
 * User accounts are now stored in PostgreSQL instead of memory.
 */
await using (var connection = new NpgsqlConnection(connectionString))
{
    await connection.OpenAsync();

    var createTableCommand = new NpgsqlCommand(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
        """,
        connection);

    await createTableCommand.ExecuteNonQueryAsync();
}

/*
 * Books are still stored in memory for this demo.
 */
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

/*
 * REGISTER
 */
app.MapPost("/api/register", async (User user) =>
{
    if (string.IsNullOrWhiteSpace(user.Username) ||
        string.IsNullOrWhiteSpace(user.Password))
    {
        return Results.BadRequest(
            "Username and password are required.");
    }

    await using var connection =
        new NpgsqlConnection(connectionString);

    await connection.OpenAsync();

    var passwordHash =
        BCrypt.Net.BCrypt.HashPassword(user.Password);

    var command = new NpgsqlCommand(
        """
        INSERT INTO users (username, password_hash)
        VALUES (@username, @passwordHash)
        ON CONFLICT (username) DO NOTHING;
        """,
        connection);

    command.Parameters.AddWithValue(
        "username",
        user.Username);

    command.Parameters.AddWithValue(
        "passwordHash",
        passwordHash);

    var rowsAffected =
        await command.ExecuteNonQueryAsync();

    if (rowsAffected == 0)
    {
        return Results.BadRequest(
            "Username already exists.");
    }

    return Results.Ok(new
    {
        message = "Registration successful"
    });
});

/*
 * LOGIN
 */
app.MapPost("/api/login", async (User loginUser) =>
{
    await using var connection =
        new NpgsqlConnection(connectionString);

    await connection.OpenAsync();

    var command = new NpgsqlCommand(
        """
        SELECT password_hash
        FROM users
        WHERE username = @username;
        """,
        connection);

    command.Parameters.AddWithValue(
        "username",
        loginUser.Username);

    var storedPasswordHash =
        await command.ExecuteScalarAsync() as string;

    if (storedPasswordHash == null)
    {
        return Results.Unauthorized();
    }

    var passwordIsValid =
        BCrypt.Net.BCrypt.Verify(
            loginUser.Password,
            storedPasswordHash);

    if (!passwordIsValid)
    {
        return Results.Unauthorized();
    }

    var claims = new[]
    {
        new Claim(
            ClaimTypes.Name,
            loginUser.Username)
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
        new JwtSecurityTokenHandler()
            .WriteToken(token);

    return Results.Ok(new
    {
        token = tokenString
    });
});

/*
 * GET BOOKS
 */
app.MapGet("/api/books", () =>
{
    return Results.Ok(books);
})
.RequireAuthorization();

/*
 * ADD BOOK
 */
app.MapPost("/api/books", (Book book) =>
{
    book.Id = books.Count == 0
        ? 1
        : books.Max(b => b.Id) + 1;

    books.Add(book);

    return Results.Ok(book);
})
.RequireAuthorization();

/*
 * EDIT BOOK
 */
app.MapPut("/api/books/{id}",
    (int id, Book updatedBook) =>
{
    var book =
        books.FirstOrDefault(b => b.Id == id);

    if (book == null)
    {
        return Results.NotFound();
    }

    book.Title = updatedBook.Title;
    book.Author = updatedBook.Author;
    book.PublicationDate =
        updatedBook.PublicationDate;

    return Results.Ok(book);
})
.RequireAuthorization();

/*
 * DELETE BOOK
 */
app.MapDelete("/api/books/{id}", (int id) =>
{
    var book =
        books.FirstOrDefault(b => b.Id == id);

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