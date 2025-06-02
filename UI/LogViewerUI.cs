using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for viewing system logs
    /// </summary>
    public class LogViewerUI
    {
        private readonly LogService _logService;
        private readonly User _currentUser;
        
        public LogViewerUI(LogService logService, User currentUser)
        {
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        }
        
        /// <summary>
        /// Shows the log viewer menu
        /// </summary>
        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("LOG VIEWER");
                
                Console.WriteLine("1. View All Logs");
                Console.WriteLine("2. View Error Logs");
                Console.WriteLine("3. View Security Logs");
                Console.WriteLine("4. View System Logs");
                Console.WriteLine("5. View Today's Logs");
                Console.WriteLine("6. Search Logs");
                Console.WriteLine("7. View Logs by User");
                Console.WriteLine("8. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ViewAllLogsAsync();
                        break;
                        
                    case "2":
                        await ViewErrorLogsAsync();
                        break;
                        
                    case "3":
                        await ViewSecurityLogsAsync();
                        break;
                        
                    case "4":
                        await ViewSystemLogsAsync();
                        break;
                        
                    case "5":
                        await ViewTodayLogsAsync();
                        break;
                        
                    case "6":
                        await SearchLogsAsync();
                        break;
                        
                    case "7":
                        await ViewLogsByUserAsync();
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
        /// Views all logs
        /// </summary>
        private async Task ViewAllLogsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALL LOGS");
                
                int page = 1;
                int pageSize = 15;
                bool viewMore = true;
                
                while (viewMore)
                {
                    var logs = await _logService.GetAllLogsAsync(page, pageSize);
                    
                    if (logs.Count == 0)
                    {
                        if (page == 1)
                        {
                            ConsoleHelper.DisplayInfo("No logs found.");
                        }
                        else
                        {
                            ConsoleHelper.DisplayInfo("No more logs to display.");
                        }
                        viewMore = false;
                    }
                    else
                    {
                        string[] headers = { "Time", "Type", "Message" };
                        
                        ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                        {
                            log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                            log.Type.ToString(),
                            log.Message
                        });
                        
                        Console.WriteLine($"\nPage {page} - Showing {logs.Count} logs");
                        Console.WriteLine("Press 'N' for next page, any other key to return to menu");
                        
                        var key = Console.ReadKey(true);
                        if (key.Key == ConsoleKey.N)
                        {
                            page++;
                        }
                        else
                        {
                            viewMore = false;
                        }
                    }
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views error logs
        /// </summary>
        private async Task ViewErrorLogsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ERROR LOGS");
                
                var logs = await _logService.GetLogsByTypeAsync(LogType.Error, 1, 50);
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No error logs found.");
                }
                else
                {
                    string[] headers = { "Time", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing error logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views security logs
        /// </summary>
        private async Task ViewSecurityLogsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("SECURITY LOGS");
                
                var logs = await _logService.GetLogsByTypeAsync(LogType.Security, 1, 50);
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No security logs found.");
                }
                else
                {
                    string[] headers = { "Time", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing security logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views system logs
        /// </summary>
        private async Task ViewSystemLogsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("SYSTEM LOGS");
                
                var logs = await _logService.GetLogsByTypeAsync(LogType.System, 1, 50);
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No system logs found.");
                }
                else
                {
                    string[] headers = { "Time", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing system logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views logs from today
        /// </summary>
        private async Task ViewTodayLogsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("TODAY'S LOGS");
                
                var logs = await _logService.GetTodayLogsAsync();
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No logs found for today.");
                }
                else
                {
                    string[] headers = { "Time", "Type", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("HH:mm:ss"),
                        log.Type.ToString(),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing today's logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Searches logs by keywords
        /// </summary>
        private async Task SearchLogsAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("SEARCH LOGS");
            
            try
            {
                Console.Write("Enter search term: ");
                string? searchTerm = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(searchTerm))
                {
                    ConsoleHelper.DisplayError("Search term is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine("Log Type (optional):");
                Console.WriteLine("1. Info");
                Console.WriteLine("2. Error");
                Console.WriteLine("3. Warning");
                Console.WriteLine("4. Security");
                Console.WriteLine("5. System");
                Console.WriteLine("6. All Types");
                Console.Write("Select type (default: All): ");
                string? typeChoice = Console.ReadLine();
                
                LogType? type = typeChoice switch
                {
                    "1" => LogType.Info,
                    "2" => LogType.Error,
                    "3" => LogType.Warning,
                    "4" => LogType.Security,
                    "5" => LogType.System,
                    _ => null // All types
                };
                
                Console.Write("Start Date (yyyy-MM-dd, optional): ");
                string? startDateStr = Console.ReadLine();
                DateTime? startDate = null;
                
                if (!string.IsNullOrWhiteSpace(startDateStr) && DateTime.TryParse(startDateStr, out DateTime parsedStartDate))
                {
                    startDate = parsedStartDate;
                }
                
                var logs = await _logService.SearchLogsAsync(searchTerm, type, startDate);
                
                Console.Clear();
                ConsoleHelper.DisplayHeader("SEARCH RESULTS");
                
                Console.WriteLine($"Search Term: \"{searchTerm}\"");
                if (type.HasValue)
                    Console.WriteLine($"Type: {type}");
                if (startDate.HasValue)
                    Console.WriteLine($"From: {startDate.Value.ToShortDateString()}");
                Console.WriteLine($"Results: {logs.Count}");
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No matching logs found.");
                }
                else
                {
                    string[] headers = { "Time", "Type", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        log.Type.ToString(),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error searching logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views logs for a specific user
        /// </summary>
        private async Task ViewLogsByUserAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("LOGS BY USER");
            
            try
            {
                Console.Write("Enter username: ");
                string? username = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(username))
                {
                    ConsoleHelper.DisplayError("Username is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var logs = await _logService.GetUserLogsAsync(username);
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"LOGS FOR USER: {username}");
                
                if (logs.Count == 0)
                {
                    ConsoleHelper.DisplayInfo($"No logs found for user {username}.");
                }
                else
                {
                    string[] headers = { "Time", "Type", "Message" };
                    
                    ConsoleHelper.DisplayTable(logs, headers, log => new string[]
                    {
                        log.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        log.Type.ToString(),
                        log.Message
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing user logs: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
