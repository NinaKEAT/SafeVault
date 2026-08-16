using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Services
{
    public class UserService : IUserService
    {
        private readonly ApplicationDbContext _db;
        private readonly IInputSanitizer _sanitizer;

        public UserService(ApplicationDbContext db, IInputSanitizer sanitizer)
        {
            _db = db;
            _sanitizer = sanitizer;
        }

        public async Task<User?> AuthenticateAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return null;

            // Parameterized query via EF Core — no string concatenation
            var user = await _db.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u => u.Username == username);

            if (user == null)
                return null;

            if (!VerifyPassword(password, user.PasswordHash))
                return null;

            return user;
        }

        public async Task<(bool Success, string Error)> RegisterAsync(RegisterViewModel model)
        {
            // Validate and sanitize inputs
            if (!_sanitizer.IsValidUsername(model.Username))
                return (false, "Invalid username. Use 3–50 alphanumeric characters or underscores.");

            if (!_sanitizer.IsValidEmail(model.Email))
                return (false, "Invalid email address.");

            if (_sanitizer.ContainsSqlInjection(model.Username) || _sanitizer.ContainsSqlInjection(model.Email))
                return (false, "Input contains invalid characters.");

            // Check for duplicate username or email (parameterized via EF Core)
            bool userExists = await _db.Users.AnyAsync(u => u.Username == model.Username);
            if (userExists)
                return (false, "Username already taken.");

            bool emailExists = await _db.Users.AnyAsync(u => u.Email == model.Email);
            if (emailExists)
                return (false, "Email already registered.");

            var user = new User
            {
                Username = model.Username.Trim(),
                Email = model.Email.Trim().ToLowerInvariant(),
                PasswordHash = HashPassword(model.Password),
                Role = "user",
                CreatedAt = DateTime.UtcNow
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return (true, string.Empty);
        }

        public async Task<(bool Success, string Error)> AdminCreateUserAsync(AdminCreateUserViewModel model)
        {
            if (!_sanitizer.IsValidUsername(model.Username))
                return (false, "Invalid username.");
            if (!_sanitizer.IsValidEmail(model.Email))
                return (false, "Invalid email address.");
            if (_sanitizer.ContainsSqlInjection(model.Username) || _sanitizer.ContainsSqlInjection(model.Email))
                return (false, "Input contains invalid characters.");
            if (model.Role != "admin" && model.Role != "user")
                return (false, "Role must be 'admin' or 'user'.");

            if (await _db.Users.AnyAsync(u => u.Username == model.Username))
                return (false, "Username already taken.");
            if (await _db.Users.AnyAsync(u => u.Email == model.Email))
                return (false, "Email already registered.");

            var user = new User
            {
                Username = model.Username.Trim(),
                Email    = model.Email.Trim().ToLowerInvariant(),
                PasswordHash = HashPassword(model.Password),
                Role      = model.Role,
                CreatedAt = DateTime.UtcNow
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return (true, string.Empty);
        }

        public async Task<(bool Success, string Error)> AdminUpdateUserAsync(AdminEditUserViewModel model)
        {
            if (!_sanitizer.IsValidUsername(model.Username))
                return (false, "Invalid username.");
            if (!_sanitizer.IsValidEmail(model.Email))
                return (false, "Invalid email address.");
            if (_sanitizer.ContainsSqlInjection(model.Username) || _sanitizer.ContainsSqlInjection(model.Email))
                return (false, "Input contains invalid characters.");
            if (model.Role != "admin" && model.Role != "user")
                return (false, "Role must be 'admin' or 'user'.");

            var user = await _db.Users.FirstOrDefaultAsync(u => u.UserID == model.UserID);
            if (user == null)
                return (false, "User not found.");

            // Check uniqueness only if the value changed
            if (user.Username != model.Username &&
                await _db.Users.AnyAsync(u => u.Username == model.Username))
                return (false, "Username already taken.");

            if (user.Email != model.Email.Trim().ToLowerInvariant() &&
                await _db.Users.AnyAsync(u => u.Email == model.Email.Trim().ToLowerInvariant()))
                return (false, "Email already registered.");

            user.Username = model.Username.Trim();
            user.Email    = model.Email.Trim().ToLowerInvariant();
            user.Role     = model.Role;

            if (!string.IsNullOrWhiteSpace(model.NewPassword))
                user.PasswordHash = HashPassword(model.NewPassword);

            await _db.SaveChangesAsync();
            return (true, string.Empty);
        }

        public async Task<(bool Success, string Error)> AdminDeleteUserAsync(int userId, string requestingAdminUsername)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.UserID == userId);
            if (user == null)
                return (false, "User not found.");

            // Prevent admin from deleting their own account
            if (user.Username == requestingAdminUsername)
                return (false, "You cannot delete your own account.");

            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return (true, string.Empty);
        }


        public async Task<IEnumerable<User>> GetAllUsersAsync()
        {
            return await _db.Users.AsNoTracking().OrderBy(u => u.CreatedAt).ToListAsync();
        }

        public async Task<User?> GetUserByIdAsync(int userId)
        {
            return await _db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.UserID == userId);
        }

        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
        }

        public bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
    }
}
