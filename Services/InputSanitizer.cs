using System.Text.RegularExpressions;
using System.Web;

namespace SafeVault.Services
{
    public class InputSanitizer : IInputSanitizer
    {
        private static readonly string[] SqlKeywords =
        {
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "TRUNCATE", "EXEC", "EXECUTE", "UNION", "CAST", "CONVERT",
            "DECLARE", "CURSOR", "FETCH", "KILL", "BACKUP", "RESTORE",
            "XP_", "SP_", "SYSOBJECTS", "SYSCOLUMNS"
        };

        private static readonly Regex SqlInjectionPattern = new Regex(
            @"(--|;|'|""|/\*|\*/|xp_|0x[0-9a-fA-F]+|\bUNION\b|\bSELECT\b|\bINSERT\b|\bDELETE\b|\bDROP\b|\bUPDATE\b|\bEXEC\b|\bEXECUTE\b|\bDECLARE\b)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // XSS patterns
        private static readonly Regex XssPattern = new Regex(
            @"(<script[\s\S]*?>[\s\S]*?<\/script>|<[^>]*on\w+\s*=|javascript\s*:|vbscript\s*:|data\s*:|<\s*iframe|<\s*object|<\s*embed|<\s*link|<\s*meta|<\s*style[\s\S]*?>[\s\S]*?<\/style>|alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|document\.write|window\.location|eval\s*\(|expression\s*\()",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex HtmlTagPattern = new Regex(
            @"<[^>]*>", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex EmailPattern = new Regex(
            @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
            RegexOptions.Compiled);

        private static readonly Regex UsernamePattern = new Regex(
            @"^[a-zA-Z0-9_]{3,50}$", RegexOptions.Compiled);

        public string SanitizeInput(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // Reject inputs containing SQL injection or XSS
            if (ContainsSqlInjection(input) || ContainsXss(input))
                throw new ArgumentException("Input contains potentially malicious content.");

            // Strip HTML tags
            string sanitized = HtmlTagPattern.Replace(input, string.Empty);

            // Trim and limit length
            sanitized = sanitized.Trim();
            if (sanitized.Length > 1000)
                sanitized = sanitized[..1000];

            // HTML-encode to prevent XSS in output
            sanitized = HttpUtility.HtmlEncode(sanitized);

            return sanitized;
        }

        public bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email) || email.Length > 100)
                return false;
            return EmailPattern.IsMatch(email);
        }

        public bool IsValidUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return false;
            return UsernamePattern.IsMatch(username);
        }

        public bool ContainsSqlInjection(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            if (SqlInjectionPattern.IsMatch(input))
                return true;

            string upper = input.ToUpperInvariant();
            return SqlKeywords.Any(keyword => upper.Contains(keyword));
        }

        public bool ContainsXss(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;
            return XssPattern.IsMatch(input);
        }
    }
}
