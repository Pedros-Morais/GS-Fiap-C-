using System;

namespace BlackoutGuard.Models
{
    /// <summary>
    /// Represents a log entry in the system
    /// </summary>
    public class LogEntry
    {
        /// <summary>
        /// The timestamp when the log entry was created
        /// </summary>
        public DateTime Timestamp { get; set; }
        
        /// <summary>
        /// The log message content
        /// </summary>
        public string Message { get; set; }
        
        /// <summary>
        /// The log level (e.g., Info, Warning, Error, Security)
        /// </summary>
        public string Level { get; set; }
        
        /// <summary>
        /// Type of log entry for UI compatibility
        /// </summary>
        public LogType Type { get; set; }
        
        /// <summary>
        /// Default constructor
        /// </summary>
        public LogEntry()
        {
            Timestamp = DateTime.UtcNow;
            Message = string.Empty;
            Level = "Info";
        }
        
        /// <summary>
        /// Constructor with parameters
        /// </summary>
        public LogEntry(DateTime timestamp, string message, string level = "Info")
        {
            Timestamp = timestamp;
            Message = message;
            Level = level;
        }
        
        /// <summary>
        /// Returns a string representation of the log entry
        /// </summary>
        public override string ToString()
        {
            return $"[{Timestamp}] [{Level}] {Message}";
        }
    }
}
