using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for threat management operations
    /// </summary>
    public class ThreatManagementUI
    {
        private readonly ThreatService _threatService;
        private readonly LogService _logService;
        private readonly User _currentUser;
        
        public ThreatManagementUI(ThreatService threatService, LogService logService, User currentUser)
        {
            _threatService = threatService ?? throw new ArgumentNullException(nameof(threatService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        }
        
        /// <summary>
        /// Shows the threat management menu
        /// </summary>
        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("THREAT MANAGEMENT");
                
                Console.WriteLine("1. View All Threats");
                Console.WriteLine("2. View Active Threats");
                Console.WriteLine("3. View High Severity Threats");
                Console.WriteLine("4. Register New Threat");
                Console.WriteLine("5. Update Threat Status");
                Console.WriteLine("6. Add Action to Threat");
                Console.WriteLine("7. View Threat Details");
                Console.WriteLine("8. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ViewAllThreatsAsync();
                        break;
                        
                    case "2":
                        await ViewActiveThreatsAsync();
                        break;
                        
                    case "3":
                        await ViewHighSeverityThreatsAsync();
                        break;
                        
                    case "4":
                        await RegisterNewThreatAsync();
                        break;
                        
                    case "5":
                        await UpdateThreatStatusAsync();
                        break;
                        
                    case "6":
                        await AddActionToThreatAsync();
                        break;
                        
                    case "7":
                        await ViewThreatDetailsAsync();
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
        /// Views all threats
        /// </summary>
        private async Task ViewAllThreatsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALL THREATS");
                
                var threats = await _threatService.GetAllThreatsAsync();
                
                if (threats.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No threats found.");
                }
                else
                {
                    string[] headers = { "ID", "Name", "Severity", "Type", "Status", "Detected At" };
                    
                    ConsoleHelper.DisplayTable(threats, headers, threat => new string[]
                    {
                        threat.Id.ToString().Substring(0, 8),
                        threat.Name,
                        threat.Severity.ToString(),
                        threat.Type.ToString(),
                        threat.Status.ToString(),
                        threat.DetectedAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing threats: {ex.Message}");
                _logService.LogError($"Error viewing threats: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views active threats
        /// </summary>
        private async Task ViewActiveThreatsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ACTIVE THREATS");
                
                var threats = await _threatService.GetActiveThreatsAsync();
                
                if (threats.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No active threats found.");
                }
                else
                {
                    string[] headers = { "ID", "Name", "Severity", "Type", "Status", "Detected At" };
                    
                    ConsoleHelper.DisplayTable(threats, headers, threat => new string[]
                    {
                        threat.Id.ToString().Substring(0, 8),
                        threat.Name,
                        threat.Severity.ToString(),
                        threat.Type.ToString(),
                        threat.Status.ToString(),
                        threat.DetectedAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing active threats: {ex.Message}");
                _logService.LogError($"Error viewing active threats: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views high severity threats
        /// </summary>
        private async Task ViewHighSeverityThreatsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("HIGH SEVERITY THREATS");
                
                var threats = await _threatService.GetHighSeverityThreatsAsync();
                
                if (threats.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No high severity threats found.");
                }
                else
                {
                    string[] headers = { "ID", "Name", "Severity", "Type", "Status", "Detected At" };
                    
                    ConsoleHelper.DisplayTable(threats, headers, threat => new string[]
                    {
                        threat.Id.ToString().Substring(0, 8),
                        threat.Name,
                        threat.Severity.ToString(),
                        threat.Type.ToString(),
                        threat.Status.ToString(),
                        threat.DetectedAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing high severity threats: {ex.Message}");
                _logService.LogError($"Error viewing high severity threats: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Registers a new threat
        /// </summary>
        private async Task RegisterNewThreatAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("REGISTER NEW THREAT");
            
            try
            {
                Console.Write("Name: ");
                string? name = Console.ReadLine();
                
                Console.Write("Description: ");
                string? description = Console.ReadLine();
                
                Console.WriteLine("\nSeverity:");
                Console.WriteLine("1. Low");
                Console.WriteLine("2. Medium");
                Console.WriteLine("3. High");
                Console.WriteLine("4. Critical");
                Console.Write("Select severity: ");
                string? severityChoice = Console.ReadLine();
                
                ThreatSeverity severity = severityChoice switch
                {
                    "1" => ThreatSeverity.Low,
                    "2" => ThreatSeverity.Medium,
                    "3" => ThreatSeverity.High,
                    "4" => ThreatSeverity.Critical,
                    _ => ThreatSeverity.Medium // Default
                };
                
                Console.WriteLine("\nThreat Type:");
                Console.WriteLine("1. Malware");
                Console.WriteLine("2. Phishing");
                Console.WriteLine("3. DDoS");
                Console.WriteLine("4. Insider");
                Console.WriteLine("5. APT");
                Console.WriteLine("6. Ransomware");
                Console.WriteLine("7. ZeroDay");
                Console.WriteLine("8. SocialEngineering");
                Console.Write("Select type: ");
                string? typeChoice = Console.ReadLine();
                
                ThreatType type = typeChoice switch
                {
                    "1" => ThreatType.Malware,
                    "2" => ThreatType.Phishing,
                    "3" => ThreatType.DDoS,
                    "4" => ThreatType.Insider,
                    "5" => ThreatType.APT,
                    "6" => ThreatType.Ransomware,
                    "7" => ThreatType.ZeroDay,
                    "8" => ThreatType.SocialEngineering,
                    _ => ThreatType.Malware // Default
                };
                
                Console.Write("\nSource: ");
                string? source = Console.ReadLine();
                
                Console.Write("\nTarget System: ");
                string? target = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(description) || 
                    string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(target))
                {
                    ConsoleHelper.DisplayError("All fields are required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Threat threat = await _threatService.CreateThreatAsync(name, description, severity, type, source, target, _currentUser.Username);
                
                ConsoleHelper.DisplaySuccess($"Threat '{threat.Name}' registered successfully with ID: {threat.Id}");
                _logService.LogSecurity($"New threat registered: {threat.Name} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error registering threat: {ex.Message}");
                _logService.LogError($"Error registering threat: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Updates a threat's status
        /// </summary>
        private async Task UpdateThreatStatusAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("UPDATE THREAT STATUS");
            
            try
            {
                Console.Write("Enter threat ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid threat ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var threat = await _threatService.GetThreatByIdAsync(id);
                
                if (threat == null)
                {
                    ConsoleHelper.DisplayError($"Threat with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nCurrent Status: {threat.Status}");
                Console.WriteLine("\nNew Status:");
                Console.WriteLine("1. Active");
                Console.WriteLine("2. Mitigated");
                Console.WriteLine("3. Resolved");
                Console.WriteLine("4. False Positive");
                Console.Write("Select new status: ");
                string? statusChoice = Console.ReadLine();
                
                ThreatStatus newStatus = statusChoice switch
                {
                    "1" => ThreatStatus.Active,
                    "2" => ThreatStatus.Mitigated,
                    "3" => ThreatStatus.Resolved,
                    "4" => ThreatStatus.FalsePositive,
                    _ => threat.Status // No change
                };
                
                if (newStatus == threat.Status)
                {
                    ConsoleHelper.DisplayInfo("Status not changed.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Write("\nStatus change reason: ");
                string? reason = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(reason))
                {
                    ConsoleHelper.DisplayError("Reason is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _threatService.UpdateThreatStatusAsync(id, newStatus, _currentUser.Username);
                await _threatService.AddThreatActionAsync(id, $"Status changed to {newStatus}. Reason: {reason}", _currentUser.Username);
                
                ConsoleHelper.DisplaySuccess($"Threat status updated to {newStatus}.");
                _logService.LogSecurity($"Threat {threat.Name} status updated from {threat.Status} to {newStatus} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error updating threat status: {ex.Message}");
                _logService.LogError($"Error updating threat status: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Adds an action to a threat
        /// </summary>
        private async Task AddActionToThreatAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ADD ACTION TO THREAT");
            
            try
            {
                Console.Write("Enter threat ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid threat ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var threat = await _threatService.GetThreatByIdAsync(id);
                
                if (threat == null)
                {
                    ConsoleHelper.DisplayError($"Threat with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nThreat: {threat.Name}");
                Console.WriteLine($"Description: {threat.Description}");
                Console.WriteLine($"Status: {threat.Status}");
                
                Console.Write("\nAction description: ");
                string? actionDescription = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(actionDescription))
                {
                    ConsoleHelper.DisplayError("Action description is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _threatService.AddThreatActionAsync(id, actionDescription, _currentUser.Username);
                
                ConsoleHelper.DisplaySuccess("Action added successfully.");
                _logService.LogInfo($"Action added to threat {threat.Name} by {_currentUser.Username}: {actionDescription}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error adding action: {ex.Message}");
                _logService.LogError($"Error adding action to threat: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views detailed information about a threat
        /// </summary>
        private async Task ViewThreatDetailsAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("THREAT DETAILS");
            
            try
            {
                Console.Write("Enter threat ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid threat ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var threat = await _threatService.GetThreatByIdAsync(id);
                
                if (threat == null)
                {
                    ConsoleHelper.DisplayError($"Threat with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"THREAT: {threat.Name}");
                
                Console.WriteLine($"ID: {threat.Id}");
                Console.WriteLine($"Name: {threat.Name}");
                Console.WriteLine($"Description: {threat.Description}");
                Console.WriteLine($"Severity: {threat.Severity}");
                Console.WriteLine($"Type: {threat.Type}");
                Console.WriteLine($"Status: {threat.Status}");
                Console.WriteLine($"Source: {threat.Source}");
                Console.WriteLine($"Detected At: {threat.DetectedAt}");
                Console.WriteLine($"Detected By: {threat.DetectedBy}");
                
                if (!string.IsNullOrWhiteSpace(threat.PotentialImpact))
                {
                    Console.WriteLine("\nPotential Impact:");
                    Console.WriteLine(threat.PotentialImpact);
                }
                
                if (!string.IsNullOrWhiteSpace(threat.RecommendedActions))
                {
                    Console.WriteLine("\nRecommended Actions:");
                    Console.WriteLine(threat.RecommendedActions);
                }
                
                Console.WriteLine("\nAction History:");
                if (threat.Actions.Count == 0)
                {
                    Console.WriteLine("No actions recorded.");
                }
                else
                {
                    foreach (var action in threat.Actions)
                    {
                        Console.WriteLine($"[{action.Timestamp}] {action.Description} (by {action.PerformedBy})");
                    }
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing threat details: {ex.Message}");
                _logService.LogError($"Error viewing threat details: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
