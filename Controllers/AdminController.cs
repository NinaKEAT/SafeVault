using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    [Authorize(Roles = "admin")]
    public class AdminController : Controller
    {
        private readonly IUserService _userService;
        private readonly IInputSanitizer _sanitizer;

        public AdminController(IUserService userService, IInputSanitizer sanitizer)
        {
            _userService = userService;
            _sanitizer   = sanitizer;
        }

        // GET /Admin/Dashboard
        public async Task<IActionResult> Dashboard()
        {
            var users = await _userService.GetAllUsersAsync();
            if (TempData["Success"] != null) ViewBag.Success = TempData["Success"];
            if (TempData["Error"]   != null) ViewBag.Error   = TempData["Error"];
            return View(users);
        }

        // GET /Admin/CreateUser
        public IActionResult CreateUser() => View(new AdminCreateUserViewModel());

        // POST /Admin/CreateUser
        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(AdminCreateUserViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (_sanitizer.ContainsSqlInjection(model.Username) ||
                _sanitizer.ContainsSqlInjection(model.Email)    ||
                _sanitizer.ContainsXss(model.Username)          ||
                _sanitizer.ContainsXss(model.Email))
            {
                ModelState.AddModelError(string.Empty, "Input contains invalid or dangerous characters.");
                return View(model);
            }

            var (success, error) = await _userService.AdminCreateUserAsync(model);
            if (!success)
            {
                ModelState.AddModelError(string.Empty, error);
                return View(model);
            }

            TempData["Success"] = $"User '{model.Username}' created successfully.";
            return RedirectToAction(nameof(Dashboard));
        }

        // GET /Admin/EditUser/5
        public async Task<IActionResult> EditUser(int id)
        {
            var user = await _userService.GetUserByIdAsync(id);
            if (user == null) return NotFound();

            var vm = new AdminEditUserViewModel
            {
                UserID   = user.UserID,
                Username = user.Username,
                Email    = user.Email,
                Role     = user.Role
            };
            return View(vm);
        }

        // POST /Admin/EditUser
        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(AdminEditUserViewModel model)
        {
            if (!ModelState.IsValid) return View(model);

            if (_sanitizer.ContainsSqlInjection(model.Username) ||
                _sanitizer.ContainsSqlInjection(model.Email)    ||
                _sanitizer.ContainsXss(model.Username)          ||
                _sanitizer.ContainsXss(model.Email))
            {
                ModelState.AddModelError(string.Empty, "Input contains invalid or dangerous characters.");
                return View(model);
            }

            var (success, error) = await _userService.AdminUpdateUserAsync(model);
            if (!success)
            {
                ModelState.AddModelError(string.Empty, error);
                return View(model);
            }

            TempData["Success"] = $"User '{model.Username}' updated successfully.";
            return RedirectToAction(nameof(Dashboard));
        }

        // POST /Admin/DeleteUser
        [HttpPost, ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var adminUsername = User.Identity?.Name ?? string.Empty;
            var (success, error) = await _userService.AdminDeleteUserAsync(id, adminUsername);

            if (!success)
                TempData["Error"] = error;
            else
                TempData["Success"] = "User deleted successfully.";

            return RedirectToAction(nameof(Dashboard));
        }
    }
}
