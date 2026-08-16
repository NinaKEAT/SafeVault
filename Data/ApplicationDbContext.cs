using Microsoft.EntityFrameworkCore;
using SafeVault.Models;

namespace SafeVault.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<FinancialRecord> FinancialRecords { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(e => e.UserID);
                entity.HasIndex(e => e.Username).IsUnique();
                entity.HasIndex(e => e.Email).IsUnique();
                entity.Property(e => e.Role).HasDefaultValue("user");
            });

            modelBuilder.Entity<FinancialRecord>(entity =>
            {
                entity.HasKey(e => e.RecordID);
                entity.HasOne(e => e.User)
                      .WithMany(u => u.FinancialRecords)
                      .HasForeignKey(e => e.UserID)
                      .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}
