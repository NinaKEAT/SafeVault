# SafeVault

An ASP.NET Core MVC application demonstrating secure-by-design web development: cookie-based authentication, role-based authorization, password hashing, input sanitization, and hardened session/cookie configuration.

## Features

- **Authentication & Authorization** — Cookie-based authentication (`Microsoft.AspNetCore.Authentication.Cookies`) with a login path, an access-denied path, and role-based authorization via `AddAuthorization()`.
- **Secure password storage** — User passwords are hashed with BCrypt (work factor 12) rather than stored in plain text.
- **Hardened session cookies** — Auth cookies are configured as `HttpOnly`, `SameSite=Strict`, with a 1-hour absolute expiration (no sliding expiration) and a secure policy matched to the request scheme.
- **Input sanitization** — A dedicated `IInputSanitizer` service is registered and used to clean/validate user input before it's processed, helping guard against injection-style attacks.
- **Data access via EF Core + SQLite** — `ApplicationDbContext` is backed by SQLite (`safevault.db`) through Entity Framework Core.
- **Production hardening** — In non-development environments, the app enables a global exception handler (`/Home/Error`) and HSTS, and always enforces HTTPS redirection.
- **Seeded demo accounts** — On startup, the database is seeded with two accounts if none exist:
  - `admin` (role: `admin`)
  - `user1` (role: `user`)

  Passwords are hashed before being stored — see [Getting Started](#getting-started) for the default demo credentials.

## Project Structure

```
SafeVault/
├── Controllers/          # MVC controllers (e.g. account/auth, home)
├── Data/                 # ApplicationDbContext (EF Core + SQLite)
├── Models/                # Domain models (e.g. User)
├── Services/              # IInputSanitizer / InputSanitizer, IUserService / UserService
├── Views/                 # Razor views for the MVC controllers
├── Tests/                 # Automated tests
├── wwwroot/                # Static assets (CSS, JS, images)
├── Program.cs              # App bootstrap, auth, middleware pipeline, DB seeding
├── SafeVault.csproj
├── appsettings.json
├── appsettings.Development.json
└── safevault.db            # SQLite database file
```

## Getting Started

### Prerequisites

- [.NET SDK](https://dotnet.microsoft.com/download) 10.0 or later

### Run the app

```bash
git clone https://github.com/NinaKEAT/SafeVault.git
cd SafeVault
dotnet build
dotnet run
```

On first run, the database is created automatically (if it doesn't already exist) and seeded with two demo accounts:

| Username | Password    | Role  |
|----------|-------------|-------|
| `admin`  | `Admin@123` | admin |
| `user1`  | `User@123`  | user  |

> ⚠️ These are demo credentials meant for local development only. Change or remove them before deploying anywhere publicly accessible.

Navigate to the URL shown in the console output and log in via `/Account/Login`.

### Run the tests

```bash
cd Tests
dotnet test
```

## Security Notes

This project is built to illustrate secure coding practices for a typical MVC + EF Core app:
- Passwords are never stored or compared in plain text (BCrypt hashing).
- Session cookies are locked down against XSS/CSRF-style cookie theft (`HttpOnly`, `SameSite=Strict`).
- User input passes through a sanitization layer before use.
- HTTPS and HSTS are enforced outside of development.
- Unhandled exceptions are redirected to a generic error page in production rather than leaking stack traces.

As with any demo/learning project, review and harden further (e.g., rotate/remove seeded credentials, add rate limiting on login, add CSRF tokens on forms if not already present via `[ValidateAntiForgeryToken]`, and move secrets out of `appsettings.json`) before using this as a template for a production system.

## Tech Stack

- ASP.NET Core MVC (.NET 10.0)
- Entity Framework Core + SQLite
- Cookie authentication & role-based authorization
- BCrypt.Net for password hashing

## Development Notes

This project was built with the assistance of GitHub Copilot, which helped scaffold the MVC controllers/views, configure cookie authentication and authorization, implement the `InputSanitizer` service, wire up EF Core with SQLite, and set up the startup database seeding logic for demo accounts.