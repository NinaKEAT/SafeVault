using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserService _userService;
        private readonly IInputSanitizer _sanitizer;

        public AccountController(IUserService userService, IInputSanitizer sanitizer)
        {
            _userService = userService;
            _sanitizer = sanitizer;
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            if (User.Identity?.IsAuthenticated == true)
                return RedirectToAction("Index", "Home");

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            if (!ModelState.IsValid)
                return View(model);

            // Guard against injection in login inputs
            if (_sanitizer.ContainsSqlInjection(model.Username) || _sanitizer.ContainsXss(model.Username))
            {
                ModelState.AddModelError(string.Empty, "Invalid characters in username.");
                return View(model);
            }

            var user = await _userService.AuthenticateAsync(model.Username, model.Password);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password.");
                return View(model);
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("UserID", user.UserID.ToString())
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal,
                new AuthenticationProperties
                {
                    IsPersistent = false,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                });

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity?.IsAuthenticated == true)
                return RedirectToAction("Index", "Home");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            // Extra sanitization checks
            if (_sanitizer.ContainsSqlInjection(model.Username) ||
                _sanitizer.ContainsSqlInjection(model.Email) ||
                _sanitizer.ContainsXss(model.Username) ||
                _sanitizer.ContainsXss(model.Email))
            {
                ModelState.AddModelError(string.Empty, "Input contains invalid or dangerous characters.");
                return View(model);
            }

            var (success, error) = await _userService.RegisterAsync(model);
            if (!success)
            {
                ModelState.AddModelError(string.Empty, error);
                return View(model);
            }

            TempData["Success"] = "Registration successful! Please log in.";
            return RedirectToAction(nameof(Login));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }

        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
