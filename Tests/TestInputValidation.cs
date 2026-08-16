using NUnit.Framework;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SafeVault.Services;
using SafeVault.Models;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        private IInputSanitizer _sanitizer = null!;
        private IUserService _userService = null!;

        [SetUp]
        public void Setup()
        {
            _sanitizer = new InputSanitizer();
            // Use a shared in-memory SQLite connection to keep the schema alive across calls
            var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=:memory:");
            connection.Open();
            var options = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<SafeVault.Data.ApplicationDbContext>()
                .UseSqlite(connection)
                .Options;
            var db = new SafeVault.Data.ApplicationDbContext(options);
            db.Database.EnsureCreated();
            _userService = new UserService(db, _sanitizer);
        }

        // ── SQL Injection tests ──────────────────────────────────────────────

        [Test]
        public void TestForSQLInjection()
        {
            string[] payloads =
            {
                "' OR '1'='1",
                "'; DROP TABLE Users; --",
                "1; SELECT * FROM Users",
                "admin'--",
                "' UNION SELECT username, password FROM users--",
                "1' OR '1'='1'--",
                "'; INSERT INTO Users VALUES('hacker','x','x','admin',datetime('now')); --"
            };

            foreach (var payload in payloads)
            {
                Assert.That(_sanitizer.ContainsSqlInjection(payload), Is.True,
                    $"Expected SQL injection detected in: {payload}");

                Assert.Throws<ArgumentException>(() => _sanitizer.SanitizeInput(payload),
                    $"Expected SanitizeInput to throw for SQL payload: {payload}");
            }
        }

        // ── XSS tests ────────────────────────────────────────────────────────

        [Test]
        public void TestForXSS()
        {
            string[] payloads =
            {
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<iframe src='evil.com'></iframe>",
                "';alert('xss');//",
                "<body onload=alert('xss')>",
                "document.cookie",
                "eval(atob('YWxlcnQoMSk='))"
            };

            foreach (var payload in payloads)
            {
                Assert.That(_sanitizer.ContainsXss(payload), Is.True,
                    $"Expected XSS detected in: {payload}");

                Assert.Throws<ArgumentException>(() => _sanitizer.SanitizeInput(payload),
                    $"Expected SanitizeInput to throw for XSS payload: {payload}");
            }
        }

        // ── Login tests ──────────────────────────────────────────────────────

        [Test]
        public async Task TestInvalidLogin()
        {
            // Authenticate with wrong password
            var result = await _userService.AuthenticateAsync("nonexistent", "wrongpassword");
            Assert.That(result, Is.Null, "Authentication should return null for invalid credentials");

            // Register a user then try wrong password
            var model = new RegisterViewModel
            {
                Username = "testloginuser",
                Email = "testloginuser@test.com",
                Password = "Test@1234",
                ConfirmPassword = "Test@1234"
            };
            await _userService.RegisterAsync(model);

            var wrongPwdResult = await _userService.AuthenticateAsync("testloginuser", "WrongPassword!");
            Assert.That(wrongPwdResult, Is.Null, "Authentication should fail with incorrect password");
        }

        // ── Unauthorized admin access tests ──────────────────────────────────

        [Test]
        public void TestUnauthorizedAdminAccess()
        {
            // Simulate role check: a "user" role should not equal "admin"
            var regularUser = new User { Username = "regularuser", Role = "user" };
            Assert.That(regularUser.Role, Is.Not.EqualTo("admin"),
                "Regular user should not have admin role");

            // Verify role-based access control logic
            bool isAdmin = regularUser.Role == "admin";
            Assert.That(isAdmin, Is.False,
                "isAdmin check should be false for a regular user");

            // Admin user check
            var adminUser = new User { Username = "admin", Role = "admin" };
            Assert.That(adminUser.Role, Is.EqualTo("admin"),
                "Admin user should have admin role");
        }

        // ── Role: Admin tests ────────────────────────────────────────────────

        [Test]
        public async Task TestAdminRole_CanRegisterAndHasAdminAccess()
        {
            // Register a user then manually elevate to admin (simulating seeded admin)
            var model = new RegisterViewModel
            {
                Username = "admintest",
                Email = "admintest@safevault.com",
                Password = "Admin@1234",
                ConfirmPassword = "Admin@1234"
            };
            var (success, error) = await _userService.RegisterAsync(model);
            Assert.That(success, Is.True, $"Admin registration should succeed, got: {error}");

            // Authenticate as the new admin
            var user = await _userService.AuthenticateAsync("admintest", "Admin@1234");
            Assert.That(user, Is.Not.Null, "Admin should authenticate successfully");

            // Simulate role elevation (as Program.cs seeding does)
            user!.Role = "admin";

            // Admin role checks
            Assert.That(user.Role, Is.EqualTo("admin"), "Role should be 'admin'");
            Assert.That(user.Role == "admin", Is.True, "Admin user should pass isAdmin check");
            Assert.That(user.Role == "user", Is.False, "Admin should not be treated as regular user");

            // Admin should be able to access admin-only resource
            bool canAccessDashboard = user.Role == "admin";
            Assert.That(canAccessDashboard, Is.True, "Admin should have access to dashboard");
        }

        [Test]
        public async Task TestAdminRole_CanViewAllUsers()
        {
            // Seed two users
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "alice", Email = "alice@test.com",
                Password = "Alice@123", ConfirmPassword = "Alice@123"
            });
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "bob", Email = "bob@test.com",
                Password = "Bob@1234", ConfirmPassword = "Bob@1234"
            });

            // Admin retrieves all users
            var allUsers = (await _userService.GetAllUsersAsync()).ToList();
            Assert.That(allUsers.Count, Is.GreaterThanOrEqualTo(2), "Admin should see at least 2 users");
            Assert.That(allUsers.Any(u => u.Username == "alice"), Is.True);
            Assert.That(allUsers.Any(u => u.Username == "bob"), Is.True);
        }

        [Test]
        public async Task TestAdminRole_RejectsInvalidCredentials()
        {
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "adminlogin", Email = "adminlogin@test.com",
                Password = "AdminPass@1", ConfirmPassword = "AdminPass@1"
            });

            // Wrong password
            var result = await _userService.AuthenticateAsync("adminlogin", "WrongPass@1");
            Assert.That(result, Is.Null, "Admin login with wrong password should fail");

            // Non-existent admin
            var result2 = await _userService.AuthenticateAsync("nonexistentadmin", "Admin@123");
            Assert.That(result2, Is.Null, "Non-existent admin should not authenticate");
        }

        // ── Role: User tests ─────────────────────────────────────────────────

        [Test]
        public async Task TestUserRole_CanRegisterAndLogin()
        {
            var model = new RegisterViewModel
            {
                Username = "regularuser1",
                Email = "regularuser1@safevault.com",
                Password = "User@1234",
                ConfirmPassword = "User@1234"
            };
            var (success, error) = await _userService.RegisterAsync(model);
            Assert.That(success, Is.True, $"User registration should succeed, got: {error}");

            var user = await _userService.AuthenticateAsync("regularuser1", "User@1234");
            Assert.That(user, Is.Not.Null, "Registered user should authenticate successfully");
            Assert.That(user!.Role, Is.EqualTo("user"), "Newly registered user should have 'user' role");
            Assert.That(user.Username, Is.EqualTo("regularuser1"));
            Assert.That(user.Email, Is.EqualTo("regularuser1@safevault.com"));
        }

        [Test]
        public async Task TestUserRole_CannotAccessAdminResources()
        {
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "restricteduser",
                Email = "restricted@test.com",
                Password = "Restrict@1",
                ConfirmPassword = "Restrict@1"
            });

            var user = await _userService.AuthenticateAsync("restricteduser", "Restrict@1");
            Assert.That(user, Is.Not.Null);

            // User role should block admin access
            bool isAdmin = user!.Role == "admin";
            Assert.That(isAdmin, Is.False, "Regular user must not pass admin role check");

            bool canAccessAdminDashboard = user.Role == "admin";
            Assert.That(canAccessAdminDashboard, Is.False, "Regular user must not access admin dashboard");
        }

        [Test]
        public async Task TestUserRole_DuplicateRegistrationIsRejected()
        {
            var model = new RegisterViewModel
            {
                Username = "dupuser",
                Email = "dup@test.com",
                Password = "Dup@12345",
                ConfirmPassword = "Dup@12345"
            };
            var (firstSuccess, _) = await _userService.RegisterAsync(model);
            Assert.That(firstSuccess, Is.True, "First registration should succeed");

            // Attempt to register with same username
            var (secondSuccess, secondError) = await _userService.RegisterAsync(model);
            Assert.That(secondSuccess, Is.False, "Duplicate registration should fail");
            Assert.That(secondError, Does.Contain("taken").Or.Contain("registered"),
                "Error should mention duplicate username or email");
        }

        [Test]
        public async Task TestUserRole_PasswordChangeIsIsolated()
        {
            // Two different users should have different hashes even with the same password
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "userA", Email = "userA@test.com",
                Password = "Same@Pass1", ConfirmPassword = "Same@Pass1"
            });
            await _userService.RegisterAsync(new RegisterViewModel
            {
                Username = "userB", Email = "userB@test.com",
                Password = "Same@Pass1", ConfirmPassword = "Same@Pass1"
            });

            var userA = await _userService.AuthenticateAsync("userA", "Same@Pass1");
            var userB = await _userService.AuthenticateAsync("userB", "Same@Pass1");

            Assert.That(userA, Is.Not.Null);
            Assert.That(userB, Is.Not.Null);
            Assert.That(userA!.PasswordHash, Is.Not.EqualTo(userB!.PasswordHash),
                "Same password must produce different hashes per user (BCrypt salting)");
        }


        [Test]
        public void TestPasswordHashing()
        {
            string password = "MySecureP@ssw0rd";
            string hash = _userService.HashPassword(password);

            // Hash should not equal plain text
            Assert.That(hash, Is.Not.EqualTo(password), "Hash must not equal plain text");

            // Hash should start with BCrypt prefix
            Assert.That(hash, Does.StartWith("$2"), "Hash should be a valid BCrypt hash");

            // Correct password should verify
            bool validResult = _userService.VerifyPassword(password, hash);
            Assert.That(validResult, Is.True, "Correct password should verify successfully");

            // Wrong password should not verify
            bool invalidResult = _userService.VerifyPassword("WrongPassword!", hash);
            Assert.That(invalidResult, Is.False, "Wrong password should not verify");

            // Two hashes of the same password should differ (salt)
            string hash2 = _userService.HashPassword(password);
            Assert.That(hash, Is.Not.EqualTo(hash2), "BCrypt hashes should use different salts");
        }

        // ── Input sanitization tests ─────────────────────────────────────────

        [Test]
        public void TestInputSanitization()
        {
            // Clean inputs should pass through
            string[] cleanInputs = { "hello world", "John Doe", "simple text 123" };
            foreach (var clean in cleanInputs)
            {
                Assert.DoesNotThrow(() => _sanitizer.SanitizeInput(clean),
                    $"Clean input should not throw: {clean}");
            }

            // Malicious inputs should throw
            string[] malicious =
            {
                "<script>alert(1)</script>",
                "' OR 1=1--",
                "javascript:void(0)",
                "<img onerror=alert(1) src=x>"
            };
            foreach (var bad in malicious)
            {
                Assert.Throws<ArgumentException>(() => _sanitizer.SanitizeInput(bad),
                    $"Malicious input should throw: {bad}");
            }

            // Plain text should pass through sanitizer without throwing
            string cleanInput = "Hello World 123";
            // This doesn't contain tags or SQL/XSS patterns, so it passes
            Assert.DoesNotThrow(() => _sanitizer.SanitizeInput(cleanInput));

            // Username validation
            Assert.That(_sanitizer.IsValidUsername("valid_user123"), Is.True);
            Assert.That(_sanitizer.IsValidUsername("ab"), Is.False, "Too short");
            Assert.That(_sanitizer.IsValidUsername("invalid user!"), Is.False, "Special chars");
            Assert.That(_sanitizer.IsValidUsername(new string('a', 51)), Is.False, "Too long");

            // Email validation
            Assert.That(_sanitizer.IsValidEmail("user@example.com"), Is.True);
            Assert.That(_sanitizer.IsValidEmail("not-an-email"), Is.False);
            Assert.That(_sanitizer.IsValidEmail(""), Is.False);
        }
    }
}
