using System;
using System.IO;
using System.Threading.Tasks;

namespace BlackoutGuard.Utils
{
    /// <summary>
    /// Utility class for file operations
    /// </summary>
    public static class FileUtil
    {
        /// <summary>
        /// Ensures a directory exists, creating it if necessary
        /// </summary>
        /// <param name="directoryPath">The path to the directory</param>
        public static void EnsureDirectoryExists(string directoryPath)
        {
            if (string.IsNullOrEmpty(directoryPath))
                throw new ArgumentException("Directory path cannot be null or empty", nameof(directoryPath));
                
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }
        }
        
        /// <summary>
        /// Writes text to a file asynchronously
        /// </summary>
        /// <param name="filePath">The path to the file</param>
        /// <param name="content">The content to write</param>
        public static async Task WriteTextAsync(string filePath, string content)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
                
            // Ensure the directory exists
            string? directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory))
            {
                EnsureDirectoryExists(directory);
            }
            
            await File.WriteAllTextAsync(filePath, content);
        }
        
        /// <summary>
        /// Reads text from a file asynchronously
        /// </summary>
        /// <param name="filePath">The path to the file</param>
        /// <returns>The content of the file</returns>
        public static async Task<string> ReadTextAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
                
            if (!File.Exists(filePath))
                throw new FileNotFoundException("File not found", filePath);
                
            return await File.ReadAllTextAsync(filePath);
        }
        
        /// <summary>
        /// Checks if a file exists
        /// </summary>
        /// <param name="filePath">The path to the file</param>
        /// <returns>True if the file exists, false otherwise</returns>
        public static bool FileExists(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                throw new ArgumentException("File path cannot be null or empty", nameof(filePath));
                
            return File.Exists(filePath);
        }
    }
}
