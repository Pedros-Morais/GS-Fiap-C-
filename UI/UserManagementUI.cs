using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for user management operations
    /// </summary>
    public class UserManagementUI
    {
        private readonly AuthService _authService;
        private readonly LogService _logService;
        private readonly User _currentUser;
        
        public UserManagementUI(AuthService authService, LogService logService, User currentUser)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
            
            // Check if user has admin rights
            if (_currentUser.Role != UserRole.Administrator)
            {
                throw new UnauthorizedAccessException("Only administrators can access user management functions");
            }
        }
        
        /// <summary>
        /// Shows the user management menu
        /// </summary>
        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("USER MANAGEMENT");
                
                Console.WriteLine("1. View All Users");
                Console.WriteLine("2. Add New User");
                Console.WriteLine("3. Change User Role");
                Console.WriteLine("4. Deactivate User");
                Console.WriteLine("5. Activate User");
                Console.WriteLine("6. Reset User Password");
                Console.WriteLine("7. View User Details");
                Console.WriteLine("8. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ViewAllUsersAsync();
                        break;
                        
                    case "2":
                        await AddNewUserAsync();
                        break;
                        
                    case "3":
                        await ChangeUserRoleAsync();
                        break;
                        
                    case "4":
                        await DeactivateUserAsync();
                        break;
                        
                    case "5":
                        await ActivateUserAsync();
                        break;
                        
                    case "6":
                        await ResetUserPasswordAsync();
                        break;
                        
                    case "7":
                        await ViewUserDetailsAsync();
                        break;
                        
                    case "8":
                        return;
                        
                    default:
                        ConsoleHelper.DisplayError("Invalid option. Please try again.");
                        ConsoleHelper.WaitForKeyPress();
                        break;
                }
            }
        }
        
        /// <summary>
        /// Views all users
        /// </summary>
        private async Task ViewAllUsersAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALL USERS");
                
                var users = await _authService.GetAllUsersAsync();
                
                if (users.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No users found.");
                }
                else
                {
                    string[] headers = { "Username", "Full Name", "Role", "Status", "Last Login" };
                    
                    ConsoleHelper.DisplayTable(users, headers, user => new string[]
                    {
                        user.Username,
                        user.FullName,
                        user.Role.ToString(),
                        user.IsActive ? "Active" : "Inactive",
                        user.LastLoginAt?.ToString("yyyy-MM-dd HH:mm") ?? "Never"
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing users: {ex.Message}");
                _logService.LogError($"Error viewing users: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Adds a new user
        /// </summary>
        private async Task AddNewUserAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ADD NEW USER");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                Console.Write("Password: ");
                string? password = ConsoleHelper.ReadPassword();
                
                Console.Write("Confirm Password: ");
                string? confirmPassword = ConsoleHelper.ReadPassword();
                
                Console.Write("Full Name: ");
                string? fullName = Console.ReadLine();
                
                Console.WriteLine("\nSelect Role:");
                Console.WriteLine("1. Administrator");
                Console.WriteLine("2. Analyst");
                Console.WriteLine("3. Operator");
                Console.WriteLine("4. Auditor");
                Console.Write("Role: ");
                string? roleChoice = Console.ReadLine();
                
                UserRole role = roleChoice switch
                {
                    "1" => UserRole.Administrator,
                    "2" => UserRole.Analyst,
                    "3" => UserRole.Operator,
                    "4" => UserRole.Auditor,
                    _ => UserRole.Operator // Default
                };
                
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password) ||
                    string.IsNullOrWhiteSpace(confirmPassword) || string.IsNullOrWhiteSpace(fullName))
                {
                    ConsoleHelper.DisplayError("All fields are required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (password != confirmPassword)
                {
                    ConsoleHelper.DisplayError("Passwords do not match.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                User newUser = await _authService.RegisterUserAsync(username, password, fullName, role);
                
                ConsoleHelper.DisplaySuccess($"User {username} added successfully as {role}.");
                _logService.LogSecurity($"New user {username} added by {_currentUser.Username} with role {role}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error adding user: {ex.Message}");
                _logService.LogError($"Error adding user: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Changes a user's role
        /// </summary>
        private async Task ChangeUserRoleAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("CHANGE USER ROLE");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var user = await _authService.GetUserByUsernameAsync(username);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError($"User {username} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                // Cannot change own role
                if (user.Username == _currentUser.Username)
                {
                    ConsoleHelper.DisplayError("You cannot change your own role.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nCurrent Role: {user.Role}");
                
                Console.WriteLine("\nSelect New Role:");
                Console.WriteLine("1. Administrator");
                Console.WriteLine("2. Analyst");
                Console.WriteLine("3. Operator");
                Console.WriteLine("4. Auditor");
                Console.Write("Role: ");
                string? roleChoice = Console.ReadLine();
                
                UserRole newRole = roleChoice switch
                {
                    "1" => UserRole.Administrator,
                    "2" => UserRole.Analyst,
                    "3" => UserRole.Operator,
                    "4" => UserRole.Auditor,
                    _ => user.Role // No change
                };
                
                if (newRole == user.Role)
                {
                    ConsoleHelper.DisplayInfo("Role not changed.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _authService.ChangeUserRoleAsync(username, newRole);
                
                ConsoleHelper.DisplaySuccess($"User {username} role changed from {user.Role} to {newRole}.");
                _logService.LogSecurity($"User {username} role changed from {user.Role} to {newRole} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error changing user role: {ex.Message}");
                _logService.LogError($"Error changing user role: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Deactivates a user
        /// </summary>
        private async Task DeactivateUserAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("DEACTIVATE USER");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var user = await _authService.GetUserByUsernameAsync(username);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError($"User {username} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                // Cannot deactivate own account
                if (user.Username == _currentUser.Username)
                {
                    ConsoleHelper.DisplayError("You cannot deactivate your own account.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (!user.IsActive)
                {
                    ConsoleHelper.DisplayError($"User {username} is already inactive.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Write("\nReason for deactivation: ");
                string? reason = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(reason))
                {
                    ConsoleHelper.DisplayError("Reason is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _authService.DeactivateUserAsync(username);
                
                ConsoleHelper.DisplaySuccess($"User {username} deactivated successfully.");
                _logService.LogSecurity($"User {username} deactivated by {_currentUser.Username}. Reason: {reason}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error deactivating user: {ex.Message}");
                _logService.LogError($"Error deactivating user: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Activates a user
        /// </summary>
        private async Task ActivateUserAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ACTIVATE USER");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var user = await _authService.GetUserByUsernameAsync(username);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError($"User {username} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (user.IsActive)
                {
                    ConsoleHelper.DisplayError($"User {username} is already active.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _authService.ActivateUserAsync(username);
                
                ConsoleHelper.DisplaySuccess($"User {username} activated successfully.");
                _logService.LogSecurity($"User {username} activated by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error activating user: {ex.Message}");
                _logService.LogError($"Error activating user: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Resets a user's password
        /// </summary>
        private async Task ResetUserPasswordAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("RESET USER PASSWORD");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var user = await _authService.GetUserByUsernameAsync(username);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError($"User {username} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Write("New Password: ");
                string? newPassword = ConsoleHelper.ReadPassword();
                
                Console.Write("Confirm New Password: ");
                string? confirmPassword = ConsoleHelper.ReadPassword();
                
                if (string.IsNullOrWhiteSpace(newPassword) || string.IsNullOrWhiteSpace(confirmPassword))
                {
                    ConsoleHelper.DisplayError("Password cannot be empty.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (newPassword != confirmPassword)
                {
                    ConsoleHelper.DisplayError("Passwords do not match.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _authService.ResetPasswordAsync(username, newPassword);
                
                ConsoleHelper.DisplaySuccess($"Password for user {username} reset successfully.");
                _logService.LogSecurity($"Password reset for user {username} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error resetting password: {ex.Message}");
                _logService.LogError($"Error resetting password: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views detailed information about a user
        /// </summary>
        private async Task ViewUserDetailsAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("USER DETAILS");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var user = await _authService.GetUserByUsernameAsync(username);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError($"User {username} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"USER: {user.Username}");
                
                Console.WriteLine($"Username: {user.Username}");
                Console.WriteLine($"Full Name: {user.FullName}");
                Console.WriteLine($"Role: {user.Role}");
                Console.WriteLine($"Status: {(user.IsActive ? "Active" : "Inactive")}");
                Console.WriteLine($"Created At: {user.CreatedAt}");
                
                if (user.LastLoginAt.HasValue)
                {
                    Console.WriteLine($"Last Login: {user.LastLoginAt}");
                }
                else
                {
                    Console.WriteLine("Last Login: Never");
                }
                
                // Show recent activity if available
                var userLogs = await _logService.GetUserLogsAsync(username, 5);
                
                if (userLogs.Count > 0)
                {
                    Console.WriteLine("\nRecent Activity:");
                    foreach (var log in userLogs)
                    {
                        Console.WriteLine($"[{log.Timestamp}] {log.Message}");
                    }
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing user details: {ex.Message}");
                _logService.LogError($"Error viewing user details: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
