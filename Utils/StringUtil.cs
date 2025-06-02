using System;
using System.Text.RegularExpressions;

namespace BlackoutGuard.Utils
{
    /// <summary>
    /// Utility class for string operations
    /// </summary>
    public static class StringUtil
    {
        /// <summary>
        /// Checks if a string is a valid email address
        /// </summary>
        /// <param name="email">The email to validate</param>
        /// <returns>True if the email is valid, false otherwise</returns>
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;
                
            try
            {
                // Simple regex for email validation
                var regex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$");
                return regex.IsMatch(email);
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Checks if a string is a valid password (at least 8 characters, containing uppercase, lowercase, and a number)
        /// </summary>
        /// <param name="password">The password to validate</param>
        /// <returns>True if the password is valid, false otherwise</returns>
        public static bool IsValidPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return false;
                
            // Check length
            if (password.Length < 8)
                return false;
                
            // Check for uppercase
            if (!Regex.IsMatch(password, "[A-Z]"))
                return false;
                
            // Check for lowercase
            if (!Regex.IsMatch(password, "[a-z]"))
                return false;
                
            // Check for number
            if (!Regex.IsMatch(password, "[0-9]"))
                return false;
                
            // Check for special character
            if (!Regex.IsMatch(password, "[^a-zA-Z0-9]"))
                return false;
                
            return true;
        }
        
        /// <summary>
        /// Truncates a string to a specified length
        /// </summary>
        /// <param name="value">The string to truncate</param>
        /// <param name="maxLength">The maximum length</param>
        /// <returns>The truncated string</returns>
        public static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value))
                return value;
                
            return value.Length <= maxLength ? value : value.Substring(0, maxLength);
        }
        
        /// <summary>
        /// Normalizes a string by trimming it and removing duplicate spaces
        /// </summary>
        /// <param name="value">The string to normalize</param>
        /// <returns>The normalized string</returns>
        public static string Normalize(string value)
        {
            if (string.IsNullOrEmpty(value))
                return string.Empty;
                
            // Trim and remove duplicate spaces
            return Regex.Replace(value.Trim(), @"\s+", " ");
        }
    }
}
