namespace SafeVault.Services
{
    public interface IInputSanitizer
    {
        /// <summary>Sanitizes user input: strips HTML/scripts, encodes for output, rejects injection patterns.</summary>
        string SanitizeInput(string input);

        bool IsValidEmail(string email);
        bool IsValidUsername(string username);

        /// <summary>Returns true if the input contains SQL injection patterns.</summary>
        bool ContainsSqlInjection(string input);

        /// <summary>Returns true if the input contains XSS patterns.</summary>
        bool ContainsXss(string input);
    }
}
