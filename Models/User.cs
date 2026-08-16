using System;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models
{
    public class User
    {
        public int UserID { get; set; }

        [Required, MaxLength(50)]
        public string Username { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        [Required, EmailAddress, MaxLength(100)]
        public string Email { get; set; } = string.Empty;

        [Required, MaxLength(20)]
        public string Role { get; set; } = "user";

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public ICollection<FinancialRecord> FinancialRecords { get; set; } = new List<FinancialRecord>();
    }
}
