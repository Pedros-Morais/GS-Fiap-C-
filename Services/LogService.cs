using System;
using System.IO;
using System.Threading.Tasks;

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
            try
            {
                var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
                var logMessage = $"[{timestamp}] [{level}] {message}";
                
                // Write to console if enabled
                if (_consoleOutput)
                {
                    // Set console color based on log level
                    Console.ForegroundColor = level switch
                    {
                        "ERROR" => ConsoleColor.Red,
                        "WARNING" => ConsoleColor.Yellow,
                        "SECURITY" => ConsoleColor.Magenta,
                        "AUDIT" => ConsoleColor.Cyan,
                        "DEBUG" => ConsoleColor.Gray,
                        _ => ConsoleColor.White
                    };
                    
                    Console.WriteLine(logMessage);
                    Console.ResetColor();
                }
                
                // Write to log file
                await File.AppendAllTextAsync(_logFilePath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                // Fallback to console if file logging fails
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"LOGGING ERROR: {ex.Message}");
                Console.WriteLine($"ORIGINAL MESSAGE: [{level}] {message}");
                Console.ResetColor();
            }
        }

        /// <summary>
        /// Gets all log entries for a specific date
        /// </summary>
        public async Task<string> GetLogsByDateAsync(DateTime date)
        {
            try
            {
                var dateStr = date.ToString("yyyy-MM-dd");
                var filePath = Path.Combine(_logDirectory, $"blackoutguard-{dateStr}.log");
                
                if (File.Exists(filePath))
                {
                    return await File.ReadAllTextAsync(filePath);
                }
                
                return $"No logs found for {dateStr}";
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error retrieving logs: {ex.Message}");
                Console.ResetColor();
                return $"Error retrieving logs: {ex.Message}";
            }
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
