using System;
using System.Security.Cryptography;
using System.Text;

namespace BlackoutGuard.Utils
{
    /// <summary>
    /// Utility class for cryptographic operations
    /// </summary>
    public static class CryptoUtil
    {
        /// <summary>
        /// Hashes a password using SHA256
        /// </summary>
        /// <param name="password">The password to hash</param>
        /// <returns>The hashed password</returns>
        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
                
            using (var sha256 = SHA256.Create())
            {
                byte[] bytes = Encoding.UTF8.GetBytes(password);
                byte[] hash = sha256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }
        
        /// <summary>
        /// Verifies a password against a hash
        /// </summary>
        /// <param name="password">The password to verify</param>
        /// <param name="hash">The hash to verify against</param>
        /// <returns>True if the password matches the hash, false otherwise</returns>
        public static bool VerifyPassword(string password, string hash)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty", nameof(password));
                
            if (string.IsNullOrEmpty(hash))
                throw new ArgumentException("Hash cannot be null or empty", nameof(hash));
                
            string passwordHash = HashPassword(password);
            return passwordHash == hash;
        }
        
        /// <summary>
        /// Generates a random string
        /// </summary>
        /// <param name="length">The length of the string to generate</param>
        /// <returns>A random string</returns>
        public static string GenerateRandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            var stringBuilder = new StringBuilder(length);
            
            for (int i = 0; i < length; i++)
            {
                stringBuilder.Append(chars[random.Next(chars.Length)]);
            }
            
            return stringBuilder.ToString();
        }
    }
}
