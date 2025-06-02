// See https://aka.ms/new-console-template for more information
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

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
            Console.WriteLine("Starting BlackoutGuard - Cybersecurity Power Outage System");
            InitializeServices();
            
            await RunApplicationAsync();
        }
        
        /// <summary>
        /// Initializes all services
        /// </summary>
        private static void InitializeServices()
        {
            try
            {
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
                        exit = await ShowAuthenticationMenuAsync();
                    }
                    else
                    {
                        // Logged in, show main menu
                        exit = await ShowMainMenuAsync();
                    }
                }
                
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
