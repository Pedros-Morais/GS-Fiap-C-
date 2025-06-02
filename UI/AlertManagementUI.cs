using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for alert management operations
    /// </summary>
    public class AlertManagementUI
    {
        private readonly AlertService _alertService;
        private readonly LogService _logService;
        private readonly User _currentUser;
        
        public AlertManagementUI(AlertService alertService, LogService logService, User currentUser)
        {
            _alertService = alertService ?? throw new ArgumentNullException(nameof(alertService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        }
        
        /// <summary>
        /// Shows the alert management menu
        /// </summary>
        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALERT MANAGEMENT");
                
                Console.WriteLine("1. View All Alerts");
                Console.WriteLine("2. View Unacknowledged Alerts");
                Console.WriteLine("3. View High Priority Alerts");
                Console.WriteLine("4. Acknowledge Alert");
                Console.WriteLine("5. Create Custom Alert");
                Console.WriteLine("6. View Alert Details");
                Console.WriteLine("7. Filter Alerts by Type");
                Console.WriteLine("8. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ViewAllAlertsAsync();
                        break;
                        
                    case "2":
                        await ViewUnacknowledgedAlertsAsync();
                        break;
                        
                    case "3":
                        await ViewHighPriorityAlertsAsync();
                        break;
                        
                    case "4":
                        await AcknowledgeAlertAsync();
                        break;
                        
                    case "5":
                        await CreateCustomAlertAsync();
                        break;
                        
                    case "6":
                        await ViewAlertDetailsAsync();
                        break;
                        
                    case "7":
                        await FilterAlertsByTypeAsync();
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
        /// Views all alerts
        /// </summary>
        private async Task ViewAllAlertsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALL ALERTS");
                
                var alerts = await _alertService.GetAllAlertsAsync();
                
                if (alerts.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No alerts found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Priority", "Type", "Status", "Triggered At" };
                    
                    ConsoleHelper.DisplayTable(alerts, headers, alert => new string[]
                    {
                        alert.Id.ToString().Substring(0, 8),
                        alert.Title,
                        alert.Priority.ToString(),
                        alert.Type.ToString(),
                        alert.Acknowledged ? "Acknowledged" : "Unacknowledged",
                        alert.TriggeredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing alerts: {ex.Message}");
                _logService.LogError($"Error viewing alerts: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views unacknowledged alerts
        /// </summary>
        private async Task ViewUnacknowledgedAlertsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("UNACKNOWLEDGED ALERTS");
                
                var alerts = await _alertService.GetUnacknowledgedAlertsAsync();
                
                if (alerts.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No unacknowledged alerts found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Priority", "Type", "Triggered At", "Source" };
                    
                    ConsoleHelper.DisplayTable(alerts, headers, alert => new string[]
                    {
                        alert.Id.ToString().Substring(0, 8),
                        alert.Title,
                        alert.Priority.ToString(),
                        alert.Type.ToString(),
                        alert.TriggeredAt.ToString("yyyy-MM-dd HH:mm"),
                        alert.Source
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing unacknowledged alerts: {ex.Message}");
                _logService.LogError($"Error viewing unacknowledged alerts: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views high priority alerts
        /// </summary>
        private async Task ViewHighPriorityAlertsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("HIGH PRIORITY ALERTS");
                
                var alerts = await _alertService.GetHighPriorityAlertsAsync();
                
                if (alerts.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No high priority alerts found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Priority", "Type", "Status", "Triggered At" };
                    
                    ConsoleHelper.DisplayTable(alerts, headers, alert => new string[]
                    {
                        alert.Id.ToString().Substring(0, 8),
                        alert.Title,
                        alert.Priority.ToString(),
                        alert.Type.ToString(),
                        alert.Acknowledged ? "Acknowledged" : "Unacknowledged",
                        alert.TriggeredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing high priority alerts: {ex.Message}");
                _logService.LogError($"Error viewing high priority alerts: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Acknowledges an alert
        /// </summary>
        private async Task AcknowledgeAlertAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ACKNOWLEDGE ALERT");
            
            try
            {
                Console.Write("Enter alert ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid alert ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var alert = await _alertService.GetAlertByIdAsync(id);
                
                if (alert == null)
                {
                    ConsoleHelper.DisplayError($"Alert with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (alert.Acknowledged)
                {
                    ConsoleHelper.DisplayError("Alert is already acknowledged.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nAlert: {alert.Title}");
                Console.WriteLine($"Priority: {alert.Priority}");
                Console.WriteLine($"Description: {alert.Description}");
                
                Console.Write("\nComments (optional): ");
                string? comments = Console.ReadLine();
                
                await _alertService.AcknowledgeAlertAsync(id, _currentUser.Username, comments ?? "");
                
                ConsoleHelper.DisplaySuccess("Alert acknowledged successfully.");
                _logService.LogInfo($"Alert {alert.Title} acknowledged by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error acknowledging alert: {ex.Message}");
                _logService.LogError($"Error acknowledging alert: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Creates a custom alert
        /// </summary>
        private async Task CreateCustomAlertAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("CREATE CUSTOM ALERT");
            
            try
            {
                Console.Write("Title: ");
                string? title = Console.ReadLine();
                
                Console.Write("Description: ");
                string? description = Console.ReadLine();
                
                Console.WriteLine("\nPriority:");
                Console.WriteLine("1. Low");
                Console.WriteLine("2. Medium");
                Console.WriteLine("3. High");
                Console.WriteLine("4. Critical");
                Console.Write("Select priority: ");
                string? priorityChoice = Console.ReadLine();
                
                AlertPriority priority = priorityChoice switch
                {
                    "1" => AlertPriority.Low,
                    "2" => AlertPriority.Medium,
                    "3" => AlertPriority.High,
                    "4" => AlertPriority.Critical,
                    _ => AlertPriority.Medium // Default
                };
                
                Console.WriteLine("\nAlert Type:");
                Console.WriteLine("1. Security");
                Console.WriteLine("2. Operational");
                Console.WriteLine("3. System");
                Console.WriteLine("4. Infrastructure");
                Console.WriteLine("5. Environmental");
                Console.Write("Select type: ");
                string? typeChoice = Console.ReadLine();
                
                AlertType type = typeChoice switch
                {
                    "1" => AlertType.Security,
                    "2" => AlertType.Operational,
                    "3" => AlertType.System,
                    "4" => AlertType.Infrastructure,
                    "5" => AlertType.Environmental,
                    _ => AlertType.System // Default
                };
                
                if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(description))
                {
                    ConsoleHelper.DisplayError("Title and description are required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var alert = await _alertService.CreateAlertAsync(
                    title, description, priority, type, "Manual", null, null);
                
                ConsoleHelper.DisplaySuccess($"Alert '{alert.Title}' created successfully with ID: {alert.Id}");
                _logService.LogInfo($"Custom alert created: {alert.Title} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error creating alert: {ex.Message}");
                _logService.LogError($"Error creating alert: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views detailed information about an alert
        /// </summary>
        private async Task ViewAlertDetailsAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ALERT DETAILS");
            
            try
            {
                Console.Write("Enter alert ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid alert ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var alert = await _alertService.GetAlertByIdAsync(id);
                
                if (alert == null)
                {
                    ConsoleHelper.DisplayError($"Alert with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"ALERT: {alert.Title}");
                
                Console.WriteLine($"ID: {alert.Id}");
                Console.WriteLine($"Title: {alert.Title}");
                Console.WriteLine($"Description: {alert.Description}");
                Console.WriteLine($"Priority: {alert.Priority}");
                Console.WriteLine($"Type: {alert.Type}");
                Console.WriteLine($"Status: {(alert.Acknowledged ? "Acknowledged" : "Unacknowledged")}");
                Console.WriteLine($"Triggered At: {alert.TriggeredAt}");
                Console.WriteLine($"Source: {alert.Source}");
                
                if (alert.RelatedIncidentId.HasValue)
                {
                    Console.WriteLine($"Related Incident ID: {alert.RelatedIncidentId}");
                }
                
                if (alert.RelatedThreatId.HasValue)
                {
                    Console.WriteLine($"Related Threat ID: {alert.RelatedThreatId}");
                }
                
                if (alert.RelatedVulnerabilityId.HasValue)
                {
                    Console.WriteLine($"Related Vulnerability ID: {alert.RelatedVulnerabilityId}");
                }
                
                if (alert.Acknowledged)
                {
                    Console.WriteLine($"\nAcknowledged By: {alert.AcknowledgedBy}");
                    Console.WriteLine($"Acknowledged At: {alert.AcknowledgedAt}");
                    
                    if (!string.IsNullOrWhiteSpace(alert.AcknowledgementComments))
                    {
                        Console.WriteLine($"Comments: {alert.AcknowledgementComments}");
                    }
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing alert details: {ex.Message}");
                _logService.LogError($"Error viewing alert details: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Filters alerts by type
        /// </summary>
        private async Task FilterAlertsByTypeAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("FILTER ALERTS BY TYPE");
            
            try
            {
                Console.WriteLine("Alert Types:");
                Console.WriteLine("1. Security");
                Console.WriteLine("2. Operational");
                Console.WriteLine("3. System");
                Console.WriteLine("4. Infrastructure");
                Console.WriteLine("5. Environmental");
                Console.Write("\nSelect type to filter by: ");
                string? typeChoice = Console.ReadLine();
                
                AlertType type = typeChoice switch
                {
                    "1" => AlertType.Security,
                    "2" => AlertType.Operational,
                    "3" => AlertType.System,
                    "4" => AlertType.Infrastructure,
                    "5" => AlertType.Environmental,
                    _ => AlertType.Security // Default
                };
                
                var alerts = await _alertService.GetAlertsByTypeAsync(type);
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"{type.ToString().ToUpper()} ALERTS");
                
                if (alerts.Count == 0)
                {
                    ConsoleHelper.DisplayInfo($"No {type} alerts found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Priority", "Status", "Triggered At" };
                    
                    ConsoleHelper.DisplayTable(alerts, headers, alert => new string[]
                    {
                        alert.Id.ToString().Substring(0, 8),
                        alert.Title,
                        alert.Priority.ToString(),
                        alert.Acknowledged ? "Acknowledged" : "Unacknowledged",
                        alert.TriggeredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error filtering alerts: {ex.Message}");
                _logService.LogError($"Error filtering alerts: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
