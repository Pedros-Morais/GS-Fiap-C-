using System;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for authentication operations
    /// </summary>
    public class AuthenticationUI
    {
        private readonly AuthService _authService;
        private readonly LogService _logService;
        
        public AuthenticationUI(AuthService authService, LogService logService)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
        }
        
        /// <summary>
        /// Shows the authentication menu
        /// </summary>
        public async Task<(bool Exit, User? User)> ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("BLACKOUT GUARD - AUTHENTICATION");
                
                Console.WriteLine("1. Login");
                Console.WriteLine("2. Register New User");
                Console.WriteLine("3. Exit");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        var user = await LoginAsync();
                        if (user != null)
                        {
                            return (false, user); // Continue to main menu with authenticated user
                        }
                        break;
                        
                    case "2":
                        await RegisterAsync();
                        break;
                        
                    case "3":
                        return (true, null); // Exit application
                        
                    default:
                        ConsoleHelper.DisplayError("Invalid option. Please try again.");
                        ConsoleHelper.WaitForKeyPress();
                        break;
                }
            }
        }
        
        /// <summary>
        /// Handles user login
        /// </summary>
        private async Task<User?> LoginAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("USER LOGIN");
            
            try
            {
                Console.Write("Username: ");
                string? username = Console.ReadLine();
                
                Console.Write("Password: ");
                string? password = ConsoleHelper.ReadPassword();
                
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                {
                    ConsoleHelper.DisplayError("Username and password cannot be empty.");
                    ConsoleHelper.WaitForKeyPress();
                    return null;
                }
                
                User? user = await _authService.LoginAsync(username, password);
                
                if (user != null)
                {
                    ConsoleHelper.DisplaySuccess($"Welcome, {user.Username}! You are logged in as {user.Role}.");
                    _logService.LogSecurity($"User {username} logged in successfully");
                }
                else
                {
                    ConsoleHelper.DisplayError("Invalid username or password.");
                    _logService.LogSecurity($"Failed login attempt for username {username}");
                }
                
                ConsoleHelper.WaitForKeyPress();
                return user;
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Login error: {ex.Message}");
                _logService.LogError($"Login error: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
                return null;
            }
        }
        
        /// <summary>
        /// Handles user registration
        /// </summary>
        private async Task RegisterAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("USER REGISTRATION");
            
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
                
                ConsoleHelper.DisplaySuccess($"User {username} registered successfully as {role}.");
                _logService.LogSecurity($"New user registered: {username} with role {role}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Registration error: {ex.Message}");
                _logService.LogError($"Registration error: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
