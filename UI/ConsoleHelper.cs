using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BlackoutGuard.Models;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Helper class for console UI operations
    /// </summary>
    public static class ConsoleHelper
    {
        /// <summary>
        /// Displays a header with proper formatting
        /// </summary>
        public static void DisplayHeader(string title)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(new string('=', Console.WindowWidth - 1));
            Console.WriteLine(title.PadLeft((Console.WindowWidth + title.Length) / 2));
            Console.WriteLine(new string('=', Console.WindowWidth - 1));
            Console.ResetColor();
            Console.WriteLine();
        }
        
        /// <summary>
        /// Displays an error message
        /// </summary>
        public static void DisplayError(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nERRO: {message}");
            Console.ResetColor();
        }
        
        /// <summary>
        /// Displays a success message
        /// </summary>
        public static void DisplaySuccess(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\nSUCESSO: {message}");
            Console.ResetColor();
        }
        
        /// <summary>
        /// Displays a warning message
        /// </summary>
        public static void DisplayWarning(string message)
        {
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"\nAVISO: {message}");
            Console.ResetColor();
        }
        
        /// <summary>
        /// Displays an information message
        /// </summary>
        public static void DisplayInfo(string message)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\nINFORMAÇÃO: {message}");
            Console.ResetColor();
        }
        
        /// <summary>
        /// Waits for any key press
        /// </summary>
        public static void WaitForKeyPress()
        {
            Console.WriteLine("\nPressione qualquer tecla para continuar...");
            Console.ReadKey(true);
        }
        
        /// <summary>
        /// Reads a password without displaying it
        /// </summary>
        public static string ReadPassword()
        {
            var password = new System.Text.StringBuilder();
            ConsoleKeyInfo key;
            
            do
            {
                key = Console.ReadKey(true);
                
                if (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Backspace)
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    password.Remove(password.Length - 1, 1);
                    Console.Write("\b \b");
                }
            } while (key.Key != ConsoleKey.Enter);
            
            Console.WriteLine();
            return password.ToString();
        }
        
        /// <summary>
        /// Displays a list of items with pagination
        /// </summary>
        public static void DisplayPaginatedList<T>(List<T> items, Func<T, string> itemFormatter, string title, int pageSize = 10)
        {
            if (items == null || items.Count == 0)
            {
                DisplayInfo("No items to display.");
                return;
            }
            
            int currentPage = 0;
            int totalPages = (int)Math.Ceiling(items.Count / (double)pageSize);
            
            while (true)
            {
                Console.Clear();
                DisplayHeader(title);
                
                int startIndex = currentPage * pageSize;
                int endIndex = Math.Min(startIndex + pageSize, items.Count);
                
                for (int i = startIndex; i < endIndex; i++)
                {
                    Console.WriteLine($"{i + 1}. {itemFormatter(items[i])}");
                }
                
                Console.WriteLine($"\nPage {currentPage + 1} of {totalPages}");
                Console.WriteLine("N: Next page, P: Previous page, Q: Return to previous menu");
                
                var key = Console.ReadKey(true);
                
                switch (char.ToUpper(key.KeyChar))
                {
                    case 'N':
                        if (currentPage < totalPages - 1)
                            currentPage++;
                        break;
                        
                    case 'P':
                        if (currentPage > 0)
                            currentPage--;
                        break;
                        
                    case 'Q':
                        return;
                }
            }
        }
        
        /// <summary>
        /// Displays a table of data
        /// </summary>
        public static void DisplayTable<T>(List<T> items, string[] headers, Func<T, string[]> rowDataSelector)
        {
            if (items == null || items.Count == 0)
            {
                DisplayInfo("No data to display.");
                return;
            }
            
            // Calculate column widths
            int[] columnWidths = new int[headers.Length];
            
            // Initialize with header lengths
            for (int i = 0; i < headers.Length; i++)
            {
                columnWidths[i] = headers[i].Length;
            }
            
            // Find maximum width for each column based on data
            foreach (var item in items)
            {
                string[] rowData = rowDataSelector(item);
                
                for (int i = 0; i < rowData.Length; i++)
                {
                    if (i < columnWidths.Length && rowData[i].Length > columnWidths[i])
                    {
                        columnWidths[i] = rowData[i].Length;
                    }
                }
            }
            
            // Add padding
            for (int i = 0; i < columnWidths.Length; i++)
            {
                columnWidths[i] += 2;
            }
            
            // Print header
            Console.ForegroundColor = ConsoleColor.White;
            for (int i = 0; i < headers.Length; i++)
            {
                Console.Write(headers[i].PadRight(columnWidths[i]));
            }
            Console.WriteLine();
            
            // Print separator
            for (int i = 0; i < headers.Length; i++)
            {
                Console.Write(new string('-', columnWidths[i]));
            }
            Console.WriteLine();
            Console.ResetColor();
            
            // Print data
            foreach (var item in items)
            {
                string[] rowData = rowDataSelector(item);
                
                for (int i = 0; i < rowData.Length && i < headers.Length; i++)
                {
                    Console.Write(rowData[i].PadRight(columnWidths[i]));
                }
                
                Console.WriteLine();
            }
        }
    }
}
