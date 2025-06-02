using System;

namespace BlackoutGuard.Models
{
    /// <summary>
    /// Represents the type of log entry
    /// </summary>
    public enum LogType
    {
        Info,       // Informational message
        Error,      // Error message
        Warning,    // Warning message
        Security,   // Security-related message
        System      // System-related message
    }
}
