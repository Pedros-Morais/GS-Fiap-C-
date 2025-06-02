using System;
using System;
using System.Collections.Generic;
using System.Linq;
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
        public async Task<User> LoginAsync(string username, string password)
        {
            try
            {
                // Get the user directly from the data store by username
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                {
                    _logService.LogWarning($"Login attempt failed: User not found: {username}");
                    return null;
                }
                
                // Check if the account is active
                if (!user.IsActive)
                {
                    _logService.LogWarning($"Login attempt failed: Account is disabled: {username}");
                    return null;
                }
                
                // Verify the password
                if (!VerifyPassword(password, user.PasswordHash, user.Salt))
                {
                    _logService.LogWarning($"Login attempt failed: Invalid password for user: {username}");
                    return null;
                }
                
                // Set the current user
                _currentUser = user;
                
                // Update last login time
                user.LastLoginAt = DateTime.UtcNow;
                
                try {
                    await _dataService.UpdateUserAsync(user);
                }
                catch (Exception updateEx)
                {
                    // Just log the error but don't fail the login
                    _logService.LogError($"Error updating last login time: {updateEx.Message}");
                }
                
                // Log the successful login
                _logService.LogInfo($"User logged in successfully: {username}");
                return user;
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
        public async Task<User> RegisterUserAsync(string username, string password, string fullName, UserRole role)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(fullName))
                    throw new ArgumentException("Full name cannot be empty", nameof(fullName));
                
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(password))
                    throw new ArgumentException("Password cannot be empty", nameof(password));
                
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
                var user = new User
                {
                    Username = username,
                    FullName = fullName,
                    PasswordHash = passwordHash,
                    Salt = salt,
                    Role = role,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    LastLoginAt = null
                };
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
        /// Gets all users in the system
        /// </summary>
        public async Task<List<User>> GetAllUsersAsync()
        {
            try
            {
                return await _dataService.GetAllUsersAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all users: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets a user by username
        /// </summary>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                return await _dataService.GetUserByUsernameAsync(username);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting user by username: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Changes a user's role
        /// </summary>
        public async Task ChangeUserRoleAsync(string username, UserRole newRole)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                    throw new InvalidOperationException($"User not found: {username}");
                
                // Don't allow changing the role of the last administrator
                if (user.Role == UserRole.Administrator && newRole != UserRole.Administrator)
                {
                    var allUsers = await _dataService.GetAllUsersAsync();
                    int adminCount = allUsers.Count(u => u.Role == UserRole.Administrator);
                    
                    if (adminCount <= 1)
                        throw new InvalidOperationException("Cannot change the role of the last administrator");
                }
                
                // Update the user's role
                user.Role = newRole;
                await _dataService.UpdateUserAsync(user);
                
                _logService.LogSecurity($"User role changed for {username} to {newRole}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error changing user role: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deactivates a user account
        /// </summary>
        public async Task DeactivateUserAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                    throw new InvalidOperationException($"User not found: {username}");
                
                // Don't allow deactivating the last administrator
                if (user.Role == UserRole.Administrator)
                {
                    var allUsers = await _dataService.GetAllUsersAsync();
                    int activeAdminCount = allUsers.Count(u => u.Role == UserRole.Administrator && u.IsActive);
                    
                    if (activeAdminCount <= 1)
                        throw new InvalidOperationException("Cannot deactivate the last administrator account");
                }
                
                // Deactivate the user
                user.IsActive = false;
                await _dataService.UpdateUserAsync(user);
                
                _logService.LogSecurity($"User account deactivated: {username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deactivating user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Activates a user account
        /// </summary>
        public async Task ActivateUserAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                    throw new InvalidOperationException($"User not found: {username}");
                
                // Activate the user
                user.IsActive = true;
                await _dataService.UpdateUserAsync(user);
                
                _logService.LogSecurity($"User account activated: {username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error activating user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Resets a user's password and generates a random password
        /// </summary>
        /// <param name="username">The username of the user</param>
        /// <returns>The newly generated random password</returns>
        public async Task<string> ResetPasswordAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                // Generate a new random password
                string newPassword = CryptoUtil.GenerateRandomString(12);
                
                // Reset the password with the generated one
                await ResetPasswordAsync(username, newPassword);
                
                return newPassword;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error resetting password: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Resets a user's password to a specified new password
        /// </summary>
        /// <param name="username">The username of the user</param>
        /// <param name="newPassword">The new password to set</param>
        /// <returns>Task representing the asynchronous operation</returns>
        public async Task ResetPasswordAsync(string username, string newPassword)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(newPassword))
                    throw new ArgumentException("New password cannot be empty", nameof(newPassword));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                    throw new InvalidOperationException($"User not found: {username}");
                
                // Hash the new password
                var salt = GenerateSalt();
                var passwordHash = HashPassword(newPassword, salt);
                
                // Update the user
                user.PasswordHash = passwordHash;
                user.Salt = salt;
                await _dataService.UpdateUserAsync(user);
                
                _logService.LogSecurity($"Password reset for user: {username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error resetting password: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Changes a user's password
        /// </summary>
        public async Task ChangePasswordAsync(string username, string newPassword)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                if (string.IsNullOrWhiteSpace(newPassword))
                    throw new ArgumentException("New password cannot be empty", nameof(newPassword));
                
                // Get the user
                var user = await _dataService.GetUserByUsernameAsync(username);
                if (user == null)
                    throw new InvalidOperationException($"User not found: {username}");
                
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
        /// Changes a user's password (with current password verification)
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
        /// Authenticates a user by username and password
        /// </summary>
        private async Task<User?> AuthenticateUserAsync(string username, string password)
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
                    return null;
                }
                
                // Check if the account is active
                if (!user.IsActive)
                {
                    _logService.LogWarning($"Login attempt failed: Account is disabled: {username}");
                    return null;
                }
                
                // Verify the password
                if (!VerifyPassword(password, user.PasswordHash, user.Salt))
                {
                    _logService.LogWarning($"Login attempt failed: Invalid password for user: {username}");
                    return null;
                }
                
                // Update last login and save
                user.LastLoginAt = DateTime.UtcNow;
                await _dataService.UpdateUserAsync(user);
                
                return user;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error during authentication: {ex.Message}");
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
