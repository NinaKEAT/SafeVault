using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    public class AdminEditUserViewModel
    {
        public int UserID { get; set; }

        [Required(ErrorMessage = "Username is required")]
        [MinLength(3), MaxLength(50)]
        [RegularExpression(@"^[a-zA-Z0-9_]+$", ErrorMessage = "Username can only contain letters, numbers, and underscores")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        [MaxLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Role is required")]
        public string Role { get; set; } = "user";

        /// <summary>
        /// Leave blank to keep the existing password unchanged.
        /// </summary>
        [DataType(DataType.Password)]
        [MinLength(8, ErrorMessage = "Password must be at least 8 characters")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            ErrorMessage = "Password must contain uppercase, lowercase, digit and special character (@  $  !  %  *  ?  &)")]
        public string? NewPassword { get; set; }
    }
}
