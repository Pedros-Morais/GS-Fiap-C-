using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Utils;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for user authentication and authorization
    /// </summary>
    public class AuthService
    {
        private readonly DataService _dataService;
        private readonly LogService _logService;
        private User? _currentUser;

        public AuthService(DataService dataService, LogService logService)
        {
            _dataService = dataService ?? throw new ArgumentNullException(nameof(dataService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
        }

        /// <summary>
        /// Gets the currently logged in user
        /// </summary>
        public User? CurrentUser => _currentUser;

        /// <summary>
        /// Checks if a user is currently logged in
        /// </summary>
        public bool IsAuthenticated => _currentUser != null;

        /// <summary>
        /// Logs in a user with the given credentials
        /// </summary>
        public async Task<bool> LoginAsync(string username, string password)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(password))
                    throw new ArgumentException("Password cannot be empty", nameof(password));
                
                // Find the user by username
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                {
                    _logService.LogWarning($"Login attempt failed: User not found: {username}");
                    return false;
                }
                
                // Check if the account is active
                if (!user.IsActive)
                {
                    _logService.LogWarning($"Login attempt failed: Account is disabled: {username}");
                    return false;
                }
                
                // Verify the password
                if (!VerifyPassword(password, user.PasswordHash, user.Salt))
                {
                    _logService.LogWarning($"Login attempt failed: Invalid password for user: {username}");
                    return false;
                }
                
                // Update last login and save
                user.UpdateLastLogin();
                await _dataService.UpdateUserAsync(user);
                
                // Set the current user
                _currentUser = user;
                
                // Log the successful login
                _logService.LogInfo($"User logged in successfully: {username}");
                return true;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error during login: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Logs out the current user
        /// </summary>
        public void Logout()
        {
            if (_currentUser != null)
            {
                _logService.LogInfo($"User logged out: {_currentUser.Username}");
                _currentUser = null;
            }
        }

        /// <summary>
        /// Registers a new user
        /// </summary>
        public async Task<User> RegisterUserAsync(string name, string username, string password, string email, UserRole role)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(name))
                    throw new ArgumentException("Name cannot be empty", nameof(name));
                
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(password))
                    throw new ArgumentException("Password cannot be empty", nameof(password));
                
                if (string.IsNullOrWhiteSpace(email))
                    throw new ArgumentException("Email cannot be empty", nameof(email));
                
                // Check if username already exists
                var existingUser = await _dataService.GetUserByUsernameAsync(username);
                if (existingUser != null)
                {
                    throw new InvalidOperationException($"Username '{username}' is already taken");
                }
                
                // Hash the password
                var salt = GenerateSalt();
                var passwordHash = HashPassword(password, salt);
                
                // Create and save the new user
                var user = new User(name, username, passwordHash, salt, email, role);
                await _dataService.SaveUserAsync(user);
                
                // Log the registration
                _logService.LogInfo($"New user registered: {username}");
                return user;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error during user registration: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Changes a user's password
        /// </summary>
        public async Task ChangePasswordAsync(string username, string currentPassword, string newPassword)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(currentPassword))
                    throw new ArgumentException("Current password cannot be empty", nameof(currentPassword));
                
                if (string.IsNullOrWhiteSpace(newPassword))
                    throw new ArgumentException("New password cannot be empty", nameof(newPassword));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                {
                    throw new InvalidOperationException($"User not found: {username}");
                }
                
                // Verify the current password
                if (!VerifyPassword(currentPassword, user.PasswordHash, user.Salt))
                {
                    throw new InvalidOperationException("Current password is incorrect");
                }
                
                // Hash the new password
                var salt = GenerateSalt();
                var passwordHash = HashPassword(newPassword, salt);
                
                // Update the user
                user.PasswordHash = passwordHash;
                user.Salt = salt;
                await _dataService.UpdateUserAsync(user);
                
                // Log the password change
                _logService.LogInfo($"Password changed for user: {username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error during password change: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Checks if the current user has the required role
        /// </summary>
        public bool HasRole(UserRole requiredRole)
        {
            if (_currentUser == null)
                return false;
                
            // Administrator role has access to everything
            if (_currentUser.Role == UserRole.Administrator)
                return true;
                
            return _currentUser.Role == requiredRole;
        }

        #region Password Helpers

        /// <summary>
        /// Generates a random salt for password hashing
        /// </summary>
        private string GenerateSalt()
        {
            byte[] saltBytes = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(saltBytes);
            }
            return Convert.ToBase64String(saltBytes);
        }

        /// <summary>
        /// Hashes a password with the given salt
        /// </summary>
        private string HashPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = password + salt;
                var saltedPasswordBytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hashBytes = sha256.ComputeHash(saltedPasswordBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        /// <summary>
        /// Verifies if a password matches the stored hash
        /// </summary>
        private bool VerifyPassword(string password, string storedHash, string salt)
        {
            var computedHash = HashPassword(password, salt);
            return computedHash == storedHash;
        }

        #endregion
    }
}
