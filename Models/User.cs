using System;
using System.Text.Json.Serialization;

namespace BlackoutGuard.Models
{
    /// <summary>
    /// Represents a user of the BlackoutGuard system
    /// </summary>
    public class User
    {
        // Unique identifier for the user
        public Guid Id { get; private set; }
        
        // User's full name
        public string FullName { get; set; }
        
        // Username for login purposes
        public string Username { get; set; }
        
        // Password hash - never store plain passwords
        public string PasswordHash { get; set; }
        
        // Salt used for password hashing
        public string Salt { get; set; }
        
        // User's email address
        public string Email { get; set; }
        
        // User's role in the system
        public UserRole Role { get; set; }
        
        // When the user was created
        public DateTime CreatedAt { get; set; }
        
        // Last login timestamp
        public DateTime? LastLoginAt { get; set; }
        
        // Whether the account is active
        public bool IsActive { get; set; }

        // Default constructor for deserialization
        public User() 
        {
            Id = Guid.NewGuid();
            CreatedAt = DateTime.UtcNow;
            IsActive = true;
        }

        // Constructor with required fields
        public User(string fullName, string username, string passwordHash, string salt, string email, UserRole role)
        {
            Id = Guid.NewGuid();
            FullName = fullName ?? throw new ArgumentNullException(nameof(fullName));
            Username = username ?? throw new ArgumentNullException(nameof(username));
            PasswordHash = passwordHash ?? throw new ArgumentNullException(nameof(passwordHash));
            Salt = salt ?? throw new ArgumentNullException(nameof(salt));
            Email = email ?? throw new ArgumentNullException(nameof(email));
            Role = role;
            CreatedAt = DateTime.UtcNow;
            IsActive = true;
        }

        /// <summary>
        /// Updates the last login timestamp
        /// </summary>
        public void UpdateLastLogin()
        {
            LastLoginAt = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Represents different roles in the system with varying permission levels
    /// </summary>
    public enum UserRole
    {
        Administrator,  // Full system access
        Analyst,        // Can view and analyze data but limited configuration
        Operator,       // Day-to-day operations
        Auditor         // Read-only access for audit purposes
    }
}
