using SafeVault.Models;

namespace SafeVault.Services
{
    public interface IUserService
    {
        Task<User?> AuthenticateAsync(string username, string password);
        Task<(bool Success, string Error)> RegisterAsync(RegisterViewModel model);
        Task<IEnumerable<User>> GetAllUsersAsync();
        Task<User?> GetUserByIdAsync(int userId);
        bool VerifyPassword(string password, string hash);
        string HashPassword(string password);

        // Admin CRUD
        Task<(bool Success, string Error)> AdminCreateUserAsync(AdminCreateUserViewModel model);
        Task<(bool Success, string Error)> AdminUpdateUserAsync(AdminEditUserViewModel model);
        Task<(bool Success, string Error)> AdminDeleteUserAsync(int userId, string requestingAdminUsername);
    }
}
