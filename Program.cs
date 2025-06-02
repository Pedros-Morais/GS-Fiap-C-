// BlackoutGuard Cybersecurity Power Outage System
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Services;
using BlackoutGuard.UI;

namespace BlackoutGuard
{
    class Program
    {
        // Service instances
        private static LogService _logService = null!;
        private static DataService _dataService = null!;
        private static AuthService _authService = null!;
        private static AlertService _alertService = null!;
        private static ThreatService _threatService = null!;
        private static IncidentService _incidentService = null!;
        private static VulnerabilityService _vulnerabilityService = null!;
        
        // Current authenticated user
        private static User? _currentUser = null;

        static async Task Main(string[] args)
        {
            Console.Title = "BlackoutGuard - Cybersecurity Power Outage System";
            InitializeServices();
            
            _logService.LogSystem("BlackoutGuard system started");
            await RunApplicationAsync();
        }
        
        /// <summary>
        /// Initializes all services
        /// </summary>
        private static void InitializeServices()
        {
            try
            {
                Console.WriteLine("Initializing BlackoutGuard services...");
                
                // Create services in the correct order (dependency chain)
                _logService = new LogService();
                _dataService = new DataService(_logService);
                _authService = new AuthService(_dataService, _logService);
                _alertService = new AlertService(_dataService, _logService);
                _threatService = new ThreatService(_dataService, _logService, _alertService);
                _incidentService = new IncidentService(_dataService, _logService, _alertService);
                _vulnerabilityService = new VulnerabilityService(_dataService, _logService, _alertService);
                
                // Create data directories if they don't exist
                _dataService.EnsureDataDirectoriesExist();
                
                _logService.LogInfo("All services initialized successfully");
                
                // Create default admin user if no users exist
                CreateDefaultAdminIfNeeded();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error initializing services: {ex.Message}");
                Console.ResetColor();
                Environment.Exit(1);
            }
        }
        
        /// <summary>
        /// Creates a default admin user if no users exist in the system
        /// </summary>
        private static void CreateDefaultAdminIfNeeded()
        {
            try
            {
                var users = _authService.GetAllUsersAsync().GetAwaiter().GetResult();
                
                if (users.Count == 0)
                {
                    Console.WriteLine("No users found. Creating default administrator account...");
                    _authService.RegisterUserAsync("admin", "BlackoutAdmin123!", "System Administrator", UserRole.Administrator)
                        .GetAwaiter().GetResult();
                    
                    Console.WriteLine("Default administrator account created.");
                    Console.WriteLine("Username: admin");
                    Console.WriteLine("Password: BlackoutAdmin123!");
                    Console.WriteLine("Please change this password after first login.");
                    
                    _logService.LogSecurity("Created default administrator account");
                    
                    Console.WriteLine("\nPress any key to continue...");
                    Console.ReadKey(true);
                }
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating default admin: {ex.Message}");
            }
        }
        
        /// <summary>
        /// Runs the main application loop
        /// </summary>
        private static async Task RunApplicationAsync()
        {
            try
            {
                bool exit = false;
                
                while (!exit)
                {
                    if (_currentUser == null)
                    {
                        // Not logged in, show authentication menu
                        var (shouldExit, user) = await ShowAuthenticationMenuAsync();
                        exit = shouldExit;
                        _currentUser = user;
                    }
                    else
                    {
                        // Logged in, show main menu
                        exit = await ShowMainMenuAsync();
                    }
                }
                
                _logService.LogSystem("BlackoutGuard system shutting down");
                Console.WriteLine("Thank you for using BlackoutGuard. Goodbye!");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Unhandled exception in main application loop: {ex.Message}");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                Console.WriteLine("The application will now exit.");
                Console.ResetColor();
            }
        }
        
        /// <summary>
        /// Shows the authentication menu
        /// </summary>
        private static async Task<(bool Exit, User? User)> ShowAuthenticationMenuAsync()
        {
            try
            {
                var authUI = new AuthenticationUI(_authService, _logService);
                return await authUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in authentication menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
                return (false, null);
            }
        }
        
        /// <summary>
        /// Shows the main application menu
        /// </summary>
        private static async Task<bool> ShowMainMenuAsync()
        {
            if (_currentUser == null)
            {
                _logService.LogError("Attempted to show main menu without logged-in user");
                return true;
            }
            
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("BLACKOUT GUARD - MAIN MENU");
                Console.WriteLine($"Logged in as: {_currentUser.Username} ({_currentUser.Role})");
                
                Console.WriteLine("\n1. Threat Management");
                Console.WriteLine("2. Incident Management");
                Console.WriteLine("3. Vulnerability Management");
                Console.WriteLine("4. Alert Management");
                Console.WriteLine("5. System Logs");
                
                // Only show user management for administrators
                if (_currentUser.Role == UserRole.Administrator)
                {
                    Console.WriteLine("6. User Management");
                }
                
                Console.WriteLine("7. My Account");
                Console.WriteLine("8. Logout");
                Console.WriteLine("9. Exit Application");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                try
                {
                    switch (choice)
                    {
                        case "1":
                            await ShowThreatManagementMenuAsync();
                            break;
                            
                        case "2":
                            await ShowIncidentManagementMenuAsync();
                            break;
                            
                        case "3":
                            await ShowVulnerabilityManagementMenuAsync();
                            break;
                            
                        case "4":
                            await ShowAlertManagementMenuAsync();
                            break;
                            
                        case "5":
                            await ShowLogViewerMenuAsync();
                            break;
                            
                        case "6":
                            if (_currentUser.Role == UserRole.Administrator)
                            {
                                await ShowUserManagementMenuAsync();
                            }
                            else
                            {
                                ConsoleHelper.DisplayError("You do not have permission to access this feature.");
                                ConsoleHelper.WaitForKeyPress();
                            }
                            break;
                            
                        case "7":
                            await ShowMyAccountMenuAsync();
                            break;
                            
                        case "8":
                            _logService.LogInfo($"User {_currentUser.Username} logged out");
                            _currentUser = null;
                            return false;
                            
                        case "9":
                            return true;
                            
                        default:
                            ConsoleHelper.DisplayError("Invalid option. Please try again.");
                            ConsoleHelper.WaitForKeyPress();
                            break;
                    }
                }
                catch (UnauthorizedAccessException ex)
                {
                    ConsoleHelper.DisplayError($"Access denied: {ex.Message}");
                    _logService.LogSecurity($"Access denied: {_currentUser.Username} attempted to access unauthorized feature: {ex.Message}");
                    ConsoleHelper.WaitForKeyPress();
                }
                catch (Exception ex)
                {
                    ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                    _logService.LogError($"Error in main menu: {ex.Message}");
                    ConsoleHelper.WaitForKeyPress();
                }
            }
        }
        
        /// <summary>
        /// Shows the threat management menu
        /// </summary>
        private static async Task ShowThreatManagementMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                var threatUI = new ThreatManagementUI(_threatService, _logService, _currentUser);
                await threatUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in threat management menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the incident management menu
        /// </summary>
        private static async Task ShowIncidentManagementMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                var incidentUI = new IncidentManagementUI(_incidentService, _logService, _currentUser);
                await incidentUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in incident management menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the vulnerability management menu
        /// </summary>
        private static async Task ShowVulnerabilityManagementMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                var vulnerabilityUI = new VulnerabilityManagementUI(_vulnerabilityService, _logService, _currentUser);
                await vulnerabilityUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in vulnerability management menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the alert management menu
        /// </summary>
        private static async Task ShowAlertManagementMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                var alertUI = new AlertManagementUI(_alertService, _logService, _currentUser);
                await alertUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in alert management menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the log viewer menu
        /// </summary>
        private static async Task ShowLogViewerMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                var logUI = new LogViewerUI(_logService, _currentUser);
                await logUI.ShowMenuAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in log viewer menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the user management menu
        /// </summary>
        private static async Task ShowUserManagementMenuAsync()
        {
            if (_currentUser == null) return;
            
            try
            {
                // Only administrators can access user management
                if (_currentUser.Role != UserRole.Administrator)
                {
                    throw new UnauthorizedAccessException("Only administrators can access user management");
                }
                
                var userUI = new UserManagementUI(_authService, _logService, _currentUser);
                await userUI.ShowMenuAsync();
            }
            catch (UnauthorizedAccessException ex)
            {
                _logService.LogSecurity($"Unauthorized access attempt to user management by {_currentUser.Username}");
                ConsoleHelper.DisplayError($"Access denied: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error in user management menu: {ex.Message}");
                ConsoleHelper.DisplayError($"An error occurred: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Shows the my account menu
        /// </summary>
        private static async Task ShowMyAccountMenuAsync()
        {
            if (_currentUser == null) return;
            
            bool exit = false;
            
            while (!exit)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("MY ACCOUNT");
                
                Console.WriteLine($"Username: {_currentUser.Username}");
                Console.WriteLine($"Full Name: {_currentUser.FullName}");
                Console.WriteLine($"Role: {_currentUser.Role}");
                Console.WriteLine($"Last Login: {_currentUser.LastLoginAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Never"}");
                
                Console.WriteLine("\n1. Change Password");
                Console.WriteLine("2. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ChangePasswordAsync();
                        break;
                        
                    case "2":
                        exit = true;
                        break;
                        
                    default:
                        ConsoleHelper.DisplayError("Invalid option. Please try again.");
                        ConsoleHelper.WaitForKeyPress();
                        break;
                }
            }
        }
        
        /// <summary>
        /// Changes the current user's password
        /// </summary>
        private static async Task ChangePasswordAsync()
        {
            if (_currentUser == null) return;
            
            Console.Clear();
            ConsoleHelper.DisplayHeader("CHANGE PASSWORD");
            
            try
            {
                Console.Write("Current Password: ");
                string? currentPassword = ConsoleHelper.ReadPassword();
                
                Console.Write("New Password: ");
                string? newPassword = ConsoleHelper.ReadPassword();
                
                Console.Write("Confirm New Password: ");
                string? confirmPassword = ConsoleHelper.ReadPassword();
                
                if (string.IsNullOrWhiteSpace(currentPassword) || string.IsNullOrWhiteSpace(newPassword) || 
                    string.IsNullOrWhiteSpace(confirmPassword))
                {
                    ConsoleHelper.DisplayError("All fields are required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (newPassword != confirmPassword)
                {
                    ConsoleHelper.DisplayError("New passwords do not match.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                // Verify current password
                var user = await _authService.LoginAsync(_currentUser.Username, currentPassword);
                
                if (user == null)
                {
                    ConsoleHelper.DisplayError("Current password is incorrect.");
                    _logService.LogSecurity($"Failed password change attempt for {_currentUser.Username} - incorrect current password");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _authService.ChangePasswordAsync(_currentUser.Username, newPassword);
                
                ConsoleHelper.DisplaySuccess("Password changed successfully.");
                _logService.LogSecurity($"Password changed for user {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error changing password: {ex.Message}");
                _logService.LogError($"Error changing password: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
