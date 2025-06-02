using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using BlackoutGuard.Models;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for system logging
    /// </summary>
    public class LogService
    {
        private readonly string _logDirectory;
        private readonly string _logFilePath;
        private readonly bool _consoleOutput;

        public LogService(string logDirectory, bool consoleOutput = true)
        {
            _logDirectory = logDirectory ?? throw new ArgumentNullException(nameof(logDirectory));
            _consoleOutput = consoleOutput;
            
            // Create log directory if it doesn't exist
            if (!Directory.Exists(_logDirectory))
            {
                Directory.CreateDirectory(_logDirectory);
            }
            
            // Initialize log file with date stamp
            var date = DateTime.Now.ToString("yyyy-MM-dd");
            _logFilePath = Path.Combine(_logDirectory, $"blackoutguard-{date}.log");
        }

        /// <summary>
        /// Logs an informational message
        /// </summary>
        public void LogInfo(string message)
        {
            LogMessageAsync("INFO", message).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs a warning message
        /// </summary>
        public void LogWarning(string message)
        {
            LogMessageAsync("WARNING", message).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs an error message
        /// </summary>
        public void LogError(string message)
        {
            LogMessageAsync("ERROR", message).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs a security-related message
        /// </summary>
        public void LogSecurity(string message)
        {
            LogMessageAsync("SECURITY", message).ConfigureAwait(false);
        }
        
        /// <summary>
        /// Logs a system-related message
        /// </summary>
        public void LogSystem(string message)
        {
            LogMessageAsync("SYSTEM", message).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs an audit message for compliance purposes
        /// </summary>
        public void LogAudit(string message)
        {
            LogMessageAsync("AUDIT", message).ConfigureAwait(false);
        }

        /// <summary>
        /// Logs a debug message (only in debug builds)
        /// </summary>
        public void LogDebug(string message)
        {
            #if DEBUG
            LogMessageAsync("DEBUG", message).ConfigureAwait(false);
            #endif
        }

        /// <summary>
        /// Internal method to log a message with specified level
        /// </summary>
        private async Task LogMessageAsync(string level, string message)
        {
            if (string.IsNullOrWhiteSpace(message))
                return;
                
            try
            {
                // Format: [timestamp] [level] message
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                var logMessage = $"[{timestamp}] [{level}] {message}";
                
                // Console output if enabled
                if (_consoleOutput)
                {
                    ConsoleColor originalColor = Console.ForegroundColor;
                    
                    // Color based on log level
                    Console.ForegroundColor = level switch
                    {
                        "ERROR" => ConsoleColor.Red,
                        "WARNING" => ConsoleColor.Yellow,
                        "SECURITY" => ConsoleColor.Magenta,
                        "AUDIT" => ConsoleColor.Cyan,
                        "DEBUG" => ConsoleColor.Gray,
                        _ => ConsoleColor.Green
                    };
                    
                    Console.WriteLine(logMessage);
                    Console.ForegroundColor = originalColor;
                }
                
                // File output
                await File.AppendAllTextAsync(_logFilePath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                // Fallback to console output if file logging fails
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error writing to log file: {ex.Message}");
                Console.WriteLine($"Original log message: [{level}] {message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Gets all log entries for a specific date
        /// </summary>
        public async Task<List<string>> GetLogsByDateAsync(DateTime date)
        {
            try
            {
                var dateString = date.ToString("yyyy-MM-dd");
                var targetLogFile = Path.Combine(_logDirectory, $"blackoutguard-{dateString}.log");
                
                if (!File.Exists(targetLogFile))
                    return new List<string>();
                    
                var logLines = await File.ReadAllLinesAsync(targetLogFile);
                return logLines.ToList();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving logs: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Gets log entries related to a specific user
        /// </summary>
        /// <param name="username">The username to filter logs for</param>
        /// <returns>A list of log entries for the specified user</returns>
        public async Task<List<LogEntry>> GetUserLogsAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                var result = new List<LogEntry>();
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                // Sort log files by date (newest first)
                Array.Sort(logFiles, (a, b) => String.Compare(b, a, StringComparison.Ordinal));
                
                foreach (var logFile in logFiles)
                {
                    var logContent = await File.ReadAllTextAsync(logFile);
                    var logLines = logContent.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
                    
                    // Filter lines containing the username
                    var userLines = logLines.Where(line => 
                        line.Contains(username, StringComparison.OrdinalIgnoreCase) || 
                        (line.Contains("User") && line.Contains(username, StringComparison.OrdinalIgnoreCase)))
                        .ToList();
                    
                    // Parse each line into a LogEntry
                    foreach (var line in userLines)
                    {
                        var logEntry = ParseLogLine(line);
                        if (logEntry != null)
                        {
                            result.Add(logEntry);
                        }
                    }
                }
                
                return result;
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving user logs: {ex.Message}");
                return new List<LogEntry>();
            }
        }

        /// <summary>
        /// Gets log entries related to a specific user with a limit on the number of entries
        /// </summary>
        /// <param name="username">The username to filter logs for</param>
        /// <param name="limit">Maximum number of log entries to return</param>
        /// <returns>A list of log entries for the specified user</returns>
        public async Task<List<LogEntry>> GetUserLogsAsync(string username, int limit)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                var result = new List<LogEntry>();
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                // Sort log files by date (newest first)
                Array.Sort(logFiles, (a, b) => String.Compare(b, a, StringComparison.Ordinal));
                
                foreach (var logFile in logFiles)
                {
                    if (limit > 0 && result.Count >= limit)
                        break;
                        
                    var logContent = await File.ReadAllTextAsync(logFile);
                    var logLines = logContent.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
                    
                    // Filter lines containing the username
                    var userLines = logLines.Where(line => 
                        line.Contains(username, StringComparison.OrdinalIgnoreCase) || 
                        (line.Contains("User") && line.Contains(username, StringComparison.OrdinalIgnoreCase)))
                        .ToList();
                    
                    foreach (var line in userLines)
                    {
                        if (limit > 0 && result.Count >= limit)
                            break;
                            
                        var logEntry = ParseLogLine(line);
                        if (logEntry != null)
                        {
                            result.Add(logEntry);
                        }
                    }
                }
                
                return result;
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving user logs: {ex.Message}");
                return new List<LogEntry>();
            }
        }

        /// <summary>
        /// Retrieves logs by type
        /// </summary>
        public async Task<List<LogEntry>> GetLogsByTypeAsync(LogType type, int page = 1, int pageSize = 20)
        {
            try
            {
                if (page < 1) page = 1;
                if (pageSize < 1) pageSize = 20;
                
                var allLogs = new List<LogEntry>();
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                // Sort log files by date (newest first)
                Array.Sort(logFiles, (a, b) => String.Compare(b, a, StringComparison.Ordinal));
                
                foreach (var logFile in logFiles)
                {
                    var logContent = await File.ReadAllTextAsync(logFile);
                    var logLines = logContent.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
                    
                    foreach (var line in logLines)
                    {
                        var logEntry = ParseLogLine(line);
                        if (logEntry != null && logEntry.Type == type)
                        {
                            allLogs.Add(logEntry);
                        }
                    }
                }
                
                // Apply pagination
                int skip = (page - 1) * pageSize;
                return allLogs.OrderByDescending(l => l.Timestamp)
                              .Skip(skip)
                              .Take(pageSize)
                              .ToList();
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving logs by type: {ex.Message}");
                return new List<LogEntry>();
            }
        }
        
        /// <summary>
        /// Retrieves all logs with pagination
        /// </summary>
        public async Task<List<LogEntry>> GetAllLogsAsync(int page = 1, int pageSize = 50)
        {
            try
            {
                if (page < 1) page = 1;
                if (pageSize < 1) pageSize = 50;
                
                var allLogs = new List<LogEntry>();
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                // Sort log files by date (newest first)
                Array.Sort(logFiles, (a, b) => String.Compare(b, a, StringComparison.Ordinal));
                
                foreach (var logFile in logFiles)
                {
                    var logContent = await File.ReadAllTextAsync(logFile);
                    var logLines = logContent.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
                    
                    foreach (var line in logLines)
                    {
                        var logEntry = ParseLogLine(line);
                        if (logEntry != null)
                        {
                            allLogs.Add(logEntry);
                        }
                    }
                }
                
                // Apply pagination
                int skip = (page - 1) * pageSize;
                return allLogs.OrderByDescending(l => l.Timestamp)
                              .Skip(skip)
                              .Take(pageSize)
                              .ToList();
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving all logs: {ex.Message}");
                return new List<LogEntry>();
            }
        }
        
        /// <summary>
        /// Retrieves logs from today
        /// </summary>
        public async Task<List<LogEntry>> GetTodayLogsAsync()
        {
            try
            {
                var today = DateTime.Today;
                var dateString = today.ToString("yyyy-MM-dd");
                var targetLogFile = Path.Combine(_logDirectory, $"blackoutguard-{dateString}.log");
                
                if (!File.Exists(targetLogFile))
                    return new List<LogEntry>();
                    
                var logLines = await File.ReadAllLinesAsync(targetLogFile);
                var result = new List<LogEntry>();
                
                foreach (var line in logLines)
                {
                    var logEntry = ParseLogLine(line);
                    if (logEntry != null)
                    {
                        result.Add(logEntry);
                    }
                }
                
                return result.OrderByDescending(l => l.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                LogError($"Error retrieving today's logs: {ex.Message}");
                return new List<LogEntry>();
            }
        }
        
        /// <summary>
        /// Searches logs using specified criteria
        /// </summary>
        public async Task<List<LogEntry>> SearchLogsAsync(string searchTerm, LogType? type = null, DateTime? startDate = null)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(searchTerm))
                    throw new ArgumentException("Search term cannot be empty", nameof(searchTerm));
                    
                var result = new List<LogEntry>();
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                // If start date specified, filter log files by date
                if (startDate.HasValue)
                {
                    logFiles = logFiles.Where(file => 
                    {
                        var fileName = Path.GetFileNameWithoutExtension(file);
                        var datePart = fileName.Replace("blackoutguard-", "");
                        
                        if (DateTime.TryParse(datePart, out var fileDate))
                        {
                            return fileDate >= startDate.Value.Date;
                        }
                        
                        return true; // Include files with invalid date format
                    }).ToArray();
                }
                
                // Sort log files by date (newest first)
                Array.Sort(logFiles, (a, b) => String.Compare(b, a, StringComparison.Ordinal));
                
                foreach (var logFile in logFiles)
                {
                    var logContent = await File.ReadAllTextAsync(logFile);
                    var logLines = logContent.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
                    
                    // Filter lines containing the search term
                    var matchingLines = logLines.Where(line => 
                        line.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    
                    foreach (var line in matchingLines)
                    {
                        var logEntry = ParseLogLine(line);
                        if (logEntry != null)
                        {
                            // Apply type filter if specified
                            if (type.HasValue && logEntry.Type != type.Value)
                                continue;
                                
                            result.Add(logEntry);
                        }
                    }
                }
                
                return result.OrderByDescending(l => l.Timestamp).ToList();
            }
            catch (Exception ex)
            {
                LogError($"Error searching logs: {ex.Message}");
                return new List<LogEntry>();
            }
        }
        
        /// <summary>
        /// Parses a log line into a LogEntry object
        /// </summary>
        private LogEntry ParseLogLine(string logLine)
        {
            try
            {
                // Example format: [2023-05-15 14:30:22] [INFO] User john.doe logged in successfully
                var match = Regex.Match(logLine, @"\[(.*?)\]\s*\[(.*?)\]\s*(.*)");
                
                if (match.Success && match.Groups.Count >= 4)
                {
                    var timestampStr = match.Groups[1].Value;
                    var level = match.Groups[2].Value;
                    var message = match.Groups[3].Value;
                    
                    if (DateTime.TryParse(timestampStr, out DateTime timestamp))
                    {
                        var logType = DetermineLogType(level, message);
                        return new LogEntry
                        {
                            Timestamp = timestamp,
                            Level = level,
                            Message = message,
                            Type = logType
                        };
                    }
                }
                
                return null;
            }
            catch
            {
                return null;
            }
        }
        
        /// <summary>
        /// Determines log type based on log level and message content
        /// </summary>
        private LogType DetermineLogType(string level, string message)
        {
            if (level.Equals("ERROR", StringComparison.OrdinalIgnoreCase))
                return LogType.Error;
            
            if (level.Equals("WARN", StringComparison.OrdinalIgnoreCase) || 
                level.Equals("WARNING", StringComparison.OrdinalIgnoreCase))
                return LogType.Warning;
            
            if (level.Equals("SECURITY", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("security", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("auth", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("login", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("password", StringComparison.OrdinalIgnoreCase))
                return LogType.Security;
            
            if (level.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("system", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("service", StringComparison.OrdinalIgnoreCase) ||
                message.Contains("server", StringComparison.OrdinalIgnoreCase))
                return LogType.System;
            
            return LogType.Info;
        }
        
        /// <summary>
        /// Purges logs older than the specified number of days
        /// </summary>
        public void PurgeOldLogs(int olderThanDays)
        {
            try
            {
                if (olderThanDays <= 0)
                    throw new ArgumentException("Days must be positive", nameof(olderThanDays));
                
                var cutoffDate = DateTime.Now.AddDays(-olderThanDays);
                var logFiles = Directory.GetFiles(_logDirectory, "blackoutguard-*.log");
                
                foreach (var logFile in logFiles)
                {
                    var fileName = Path.GetFileNameWithoutExtension(logFile);
                    var datePart = fileName.Replace("blackoutguard-", "");
                    
                    if (DateTime.TryParse(datePart, out var fileDate))
                    {
                        if (fileDate < cutoffDate)
                        {
                            File.Delete(logFile);
                            LogInfo($"Purged old log file: {fileName}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error purging old logs: {ex.Message}");
                Console.ResetColor();
            }
        }
    }
}
