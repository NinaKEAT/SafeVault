using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddScoped<IInputSanitizer, InputSanitizer>();
builder.Services.AddScoped<IUserService, UserService>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromHours(1);
        options.SlidingExpiration = false;
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seed the database with default users
await SeedDatabase(app);

app.Run();

static async Task SeedDatabase(WebApplication app)
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.EnsureCreatedAsync();

    if (!db.Users.Any())
    {
        var users = new[]
        {
            new User
            {
                Username = "admin",
                Email = "admin@safevault.local",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123", workFactor: 12),
                Role = "admin",
                CreatedAt = DateTime.UtcNow
            },
            new User
            {
                Username = "user1",
                Email = "user1@safevault.local",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("User@123", workFactor: 12),
                Role = "user",
                CreatedAt = DateTime.UtcNow
            }
        };
        db.Users.AddRange(users);
        await db.SaveChangesAsync();
    }
}
