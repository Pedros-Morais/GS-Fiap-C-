using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using BlackoutGuard.Models;
using BlackoutGuard.Services;

namespace BlackoutGuard.UI
{
    /// <summary>
    /// Provides user interface for incident management operations
    /// </summary>
    public class IncidentManagementUI
    {
        private readonly IncidentService _incidentService;
        private readonly LogService _logService;
        private readonly User _currentUser;
        
        public IncidentManagementUI(IncidentService incidentService, LogService logService, User currentUser)
        {
            _incidentService = incidentService ?? throw new ArgumentNullException(nameof(incidentService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _currentUser = currentUser ?? throw new ArgumentNullException(nameof(currentUser));
        }
        
        /// <summary>
        /// Shows the incident management menu
        /// </summary>
        public async Task ShowMenuAsync()
        {
            while (true)
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("INCIDENT MANAGEMENT");
                
                Console.WriteLine("1. View All Incidents");
                Console.WriteLine("2. View Open Incidents");
                Console.WriteLine("3. View High Severity Incidents");
                Console.WriteLine("4. Register New Incident");
                Console.WriteLine("5. Update Incident Status");
                Console.WriteLine("6. Add Action to Incident");
                Console.WriteLine("7. Assign Incident");
                Console.WriteLine("8. Resolve Incident");
                Console.WriteLine("9. View Incident Details");
                Console.WriteLine("10. Return to Main Menu");
                
                Console.Write("\nSelect an option: ");
                string? choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await ViewAllIncidentsAsync();
                        break;
                        
                    case "2":
                        await ViewOpenIncidentsAsync();
                        break;
                        
                    case "3":
                        await ViewHighSeverityIncidentsAsync();
                        break;
                        
                    case "4":
                        await RegisterNewIncidentAsync();
                        break;
                        
                    case "5":
                        await UpdateIncidentStatusAsync();
                        break;
                        
                    case "6":
                        await AddActionToIncidentAsync();
                        break;
                        
                    case "7":
                        await AssignIncidentAsync();
                        break;
                        
                    case "8":
                        await ResolveIncidentAsync();
                        break;
                        
                    case "9":
                        await ViewIncidentDetailsAsync();
                        break;
                        
                    case "10":
                        return;
                        
                    default:
                        ConsoleHelper.DisplayError("Invalid option. Please try again.");
                        ConsoleHelper.WaitForKeyPress();
                        break;
                }
            }
        }
        
        /// <summary>
        /// Views all incidents
        /// </summary>
        private async Task ViewAllIncidentsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("ALL INCIDENTS");
                
                var incidents = await _incidentService.GetAllIncidentsAsync();
                
                if (incidents.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No incidents found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Severity", "Type", "Status", "Location", "Occurred At" };
                    
                    ConsoleHelper.DisplayTable(incidents, headers, incident => new string[]
                    {
                        incident.Id.ToString().Substring(0, 8),
                        incident.Title,
                        incident.Severity.ToString(),
                        incident.Type.ToString(),
                        incident.Status.ToString(),
                        incident.Location,
                        incident.OccurredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing incidents: {ex.Message}");
                _logService.LogError($"Error viewing incidents: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views open incidents
        /// </summary>
        private async Task ViewOpenIncidentsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("OPEN INCIDENTS");
                
                var incidents = await _incidentService.GetOpenIncidentsAsync();
                
                if (incidents.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No open incidents found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Severity", "Type", "Status", "Location", "Occurred At" };
                    
                    ConsoleHelper.DisplayTable(incidents, headers, incident => new string[]
                    {
                        incident.Id.ToString().Substring(0, 8),
                        incident.Title,
                        incident.Severity.ToString(),
                        incident.Type.ToString(),
                        incident.Status.ToString(),
                        incident.Location,
                        incident.OccurredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing open incidents: {ex.Message}");
                _logService.LogError($"Error viewing open incidents: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views high severity incidents
        /// </summary>
        private async Task ViewHighSeverityIncidentsAsync()
        {
            try
            {
                Console.Clear();
                ConsoleHelper.DisplayHeader("HIGH SEVERITY INCIDENTS");
                
                var incidents = await _incidentService.GetHighSeverityIncidentsAsync();
                
                if (incidents.Count == 0)
                {
                    ConsoleHelper.DisplayInfo("No high severity incidents found.");
                }
                else
                {
                    string[] headers = { "ID", "Title", "Severity", "Type", "Status", "Location", "Occurred At" };
                    
                    ConsoleHelper.DisplayTable(incidents, headers, incident => new string[]
                    {
                        incident.Id.ToString().Substring(0, 8),
                        incident.Title,
                        incident.Severity.ToString(),
                        incident.Type.ToString(),
                        incident.Status.ToString(),
                        incident.Location,
                        incident.OccurredAt.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing high severity incidents: {ex.Message}");
                _logService.LogError($"Error viewing high severity incidents: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Registers a new incident
        /// </summary>
        private async Task RegisterNewIncidentAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("REGISTER NEW INCIDENT");
            
            try
            {
                Console.Write("Title: ");
                string? title = Console.ReadLine();
                
                Console.Write("Description: ");
                string? description = Console.ReadLine();
                
                Console.Write("Location: ");
                string? location = Console.ReadLine();
                
                Console.Write("When did it occur? (yyyy-MM-dd HH:mm): ");
                string? occurredAtStr = Console.ReadLine();
                
                if (!DateTime.TryParse(occurredAtStr, out DateTime occurredAt))
                {
                    occurredAt = DateTime.UtcNow; // Default to now if parsing fails
                }
                
                Console.WriteLine("\nSeverity:");
                Console.WriteLine("1. Low");
                Console.WriteLine("2. Medium");
                Console.WriteLine("3. High");
                Console.WriteLine("4. Critical");
                Console.Write("Select severity: ");
                string? severityChoice = Console.ReadLine();
                
                IncidentSeverity severity = severityChoice switch
                {
                    "1" => IncidentSeverity.Low,
                    "2" => IncidentSeverity.Medium,
                    "3" => IncidentSeverity.High,
                    "4" => IncidentSeverity.Critical,
                    _ => IncidentSeverity.Medium // Default
                };
                
                Console.WriteLine("\nIncident Type:");
                Console.WriteLine("1. PowerOutage");
                Console.WriteLine("2. EquipmentFailure");
                Console.WriteLine("3. CyberAttack");
                Console.WriteLine("4. PhysicalAttack");
                Console.WriteLine("5. NaturalDisaster");
                Console.WriteLine("6. Other");
                Console.Write("Select type: ");
                string? typeChoice = Console.ReadLine();
                
                IncidentType type = typeChoice switch
                {
                    "1" => IncidentType.PowerOutage,
                    "2" => IncidentType.EquipmentFailure,
                    "3" => IncidentType.CyberAttack,
                    "4" => IncidentType.PhysicalAttack,
                    "5" => IncidentType.NaturalDisaster,
                    "6" => IncidentType.Other,
                    _ => IncidentType.Other // Default
                };
                
                if (string.IsNullOrWhiteSpace(title) || string.IsNullOrWhiteSpace(description) || string.IsNullOrWhiteSpace(location))
                {
                    ConsoleHelper.DisplayError("Title, description, and location are required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine("\nIs this incident related to a known threat? (y/n): ");
                string? relatedToThreat = Console.ReadLine()?.ToLower();
                
                if (relatedToThreat == "y" || relatedToThreat == "yes")
                {
                    Console.Write("Enter threat ID: ");
                    string? threatIdStr = Console.ReadLine();
                    
                    if (!string.IsNullOrWhiteSpace(threatIdStr) && Guid.TryParse(threatIdStr, out Guid threatId))
                    {
                        var incident = await _incidentService.CreateThreatRelatedIncidentAsync(
                            title, description, occurredAt, severity, type, location, _currentUser.Username, threatId);
                        
                        ConsoleHelper.DisplaySuccess($"Incident '{incident.Title}' registered successfully with ID: {incident.Id}");
                        _logService.LogInfo($"New incident registered: {incident.Title} by {_currentUser.Username}, related to threat {threatId}");
                    }
                    else
                    {
                        ConsoleHelper.DisplayError("Invalid threat ID format. Creating incident without threat relation.");
                        var incident = await _incidentService.CreateIncidentAsync(
                            title, description, occurredAt, severity, type, location, _currentUser.Username);
                        
                        ConsoleHelper.DisplaySuccess($"Incident '{incident.Title}' registered successfully with ID: {incident.Id}");
                        _logService.LogInfo($"New incident registered: {incident.Title} by {_currentUser.Username}");
                    }
                }
                else
                {
                    var incident = await _incidentService.CreateIncidentAsync(
                        title, description, occurredAt, severity, type, location, _currentUser.Username);
                    
                    ConsoleHelper.DisplaySuccess($"Incident '{incident.Title}' registered successfully with ID: {incident.Id}");
                    _logService.LogInfo($"New incident registered: {incident.Title} by {_currentUser.Username}");
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error registering incident: {ex.Message}");
                _logService.LogError($"Error registering incident: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Updates an incident's status
        /// </summary>
        private async Task UpdateIncidentStatusAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("UPDATE INCIDENT STATUS");
            
            try
            {
                Console.Write("Enter incident ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid incident ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var incident = await _incidentService.GetIncidentByIdAsync(id);
                
                if (incident == null)
                {
                    ConsoleHelper.DisplayError($"Incident with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nCurrent Status: {incident.Status}");
                Console.WriteLine("\nNew Status:");
                Console.WriteLine("1. Open");
                Console.WriteLine("2. InProgress");
                Console.WriteLine("3. Pending");
                Console.WriteLine("4. Resolved");
                Console.WriteLine("5. Closed");
                Console.Write("Select new status: ");
                string? statusChoice = Console.ReadLine();
                
                IncidentStatus newStatus = statusChoice switch
                {
                    "1" => IncidentStatus.Open,
                    "2" => IncidentStatus.InProgress,
                    "3" => IncidentStatus.Pending,
                    "4" => IncidentStatus.Resolved,
                    "5" => IncidentStatus.Closed,
                    _ => incident.Status // No change
                };
                
                if (newStatus == incident.Status)
                {
                    ConsoleHelper.DisplayInfo("Status not changed.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _incidentService.UpdateIncidentStatusAsync(id, newStatus, _currentUser.Username);
                
                ConsoleHelper.DisplaySuccess($"Incident status updated to {newStatus}.");
                _logService.LogInfo($"Incident {incident.Title} status updated from {incident.Status} to {newStatus} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error updating incident status: {ex.Message}");
                _logService.LogError($"Error updating incident status: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Adds an action to an incident
        /// </summary>
        private async Task AddActionToIncidentAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ADD ACTION TO INCIDENT");
            
            try
            {
                Console.Write("Enter incident ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid incident ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var incident = await _incidentService.GetIncidentByIdAsync(id);
                
                if (incident == null)
                {
                    ConsoleHelper.DisplayError($"Incident with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nIncident: {incident.Title}");
                Console.WriteLine($"Status: {incident.Status}");
                
                Console.Write("\nAction description: ");
                string? actionDescription = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(actionDescription))
                {
                    ConsoleHelper.DisplayError("Action description is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _incidentService.AddIncidentActionAsync(id, actionDescription, _currentUser.Username);
                
                ConsoleHelper.DisplaySuccess("Action added successfully.");
                _logService.LogInfo($"Action added to incident {incident.Title} by {_currentUser.Username}: {actionDescription}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error adding action: {ex.Message}");
                _logService.LogError($"Error adding action to incident: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Assigns an incident to a user
        /// </summary>
        private async Task AssignIncidentAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("ASSIGN INCIDENT");
            
            try
            {
                Console.Write("Enter incident ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid incident ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var incident = await _incidentService.GetIncidentByIdAsync(id);
                
                if (incident == null)
                {
                    ConsoleHelper.DisplayError($"Incident with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nIncident: {incident.Title}");
                Console.WriteLine($"Current Assignee: {(string.IsNullOrEmpty(incident.AssignedTo) ? "None" : incident.AssignedTo)}");
                
                Console.Write("\nAssign to (username): ");
                string? assignee = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(assignee))
                {
                    ConsoleHelper.DisplayError("Assignee is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _incidentService.AssignIncidentAsync(id, assignee);
                
                ConsoleHelper.DisplaySuccess($"Incident assigned to {assignee} successfully.");
                _logService.LogInfo($"Incident {incident.Title} assigned to {assignee} by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error assigning incident: {ex.Message}");
                _logService.LogError($"Error assigning incident: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Resolves an incident
        /// </summary>
        private async Task ResolveIncidentAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("RESOLVE INCIDENT");
            
            try
            {
                Console.Write("Enter incident ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid incident ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var incident = await _incidentService.GetIncidentByIdAsync(id);
                
                if (incident == null)
                {
                    ConsoleHelper.DisplayError($"Incident with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                if (incident.Status == IncidentStatus.Resolved || incident.Status == IncidentStatus.Closed)
                {
                    ConsoleHelper.DisplayError($"Incident is already {incident.Status}.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.WriteLine($"\nIncident: {incident.Title}");
                Console.WriteLine($"Status: {incident.Status}");
                
                Console.Write("\nRoot cause: ");
                string? rootCause = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(rootCause))
                {
                    ConsoleHelper.DisplayError("Root cause is required.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Write("Actual duration (minutes): ");
                string? durationStr = Console.ReadLine();
                
                if (!int.TryParse(durationStr, out int duration) || duration <= 0)
                {
                    ConsoleHelper.DisplayError("Valid duration is required (positive number).");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                await _incidentService.ResolveIncidentAsync(id, _currentUser.Username, rootCause, duration);
                
                ConsoleHelper.DisplaySuccess("Incident resolved successfully.");
                _logService.LogInfo($"Incident {incident.Title} resolved by {_currentUser.Username}");
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error resolving incident: {ex.Message}");
                _logService.LogError($"Error resolving incident: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
        
        /// <summary>
        /// Views detailed information about an incident
        /// </summary>
        private async Task ViewIncidentDetailsAsync()
        {
            Console.Clear();
            ConsoleHelper.DisplayHeader("INCIDENT DETAILS");
            
            try
            {
                Console.Write("Enter incident ID: ");
                string? idInput = Console.ReadLine();
                
                if (string.IsNullOrWhiteSpace(idInput) || !Guid.TryParse(idInput, out Guid id))
                {
                    ConsoleHelper.DisplayError("Invalid incident ID.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                var incident = await _incidentService.GetIncidentByIdAsync(id);
                
                if (incident == null)
                {
                    ConsoleHelper.DisplayError($"Incident with ID {id} not found.");
                    ConsoleHelper.WaitForKeyPress();
                    return;
                }
                
                Console.Clear();
                ConsoleHelper.DisplayHeader($"INCIDENT: {incident.Title}");
                
                Console.WriteLine($"ID: {incident.Id}");
                Console.WriteLine($"Title: {incident.Title}");
                Console.WriteLine($"Description: {incident.Description}");
                Console.WriteLine($"Severity: {incident.Severity}");
                Console.WriteLine($"Type: {incident.Type}");
                Console.WriteLine($"Status: {incident.Status}");
                Console.WriteLine($"Location: {incident.Location}");
                Console.WriteLine($"Occurred At: {incident.OccurredAt}");
                Console.WriteLine($"Reported By: {incident.ReportedBy}");
                Console.WriteLine($"Assigned To: {(string.IsNullOrEmpty(incident.AssignedTo) ? "None" : incident.AssignedTo)}");
                Console.WriteLine($"Estimated Duration: {incident.EstimatedDuration} minutes");
                Console.WriteLine($"Affected Users: {incident.AffectedUsers}");
                
                if (incident.RelatedThreatId.HasValue)
                {
                    Console.WriteLine($"Related Threat ID: {incident.RelatedThreatId}");
                }
                
                if (!string.IsNullOrWhiteSpace(incident.RootCause))
                {
                    Console.WriteLine("\nRoot Cause:");
                    Console.WriteLine(incident.RootCause);
                }
                
                Console.WriteLine("\nAction History:");
                if (incident.Actions.Count == 0)
                {
                    Console.WriteLine("No actions recorded.");
                }
                else
                {
                    foreach (var action in incident.Actions)
                    {
                        Console.WriteLine($"[{action.Timestamp}] {action.Description} (by {action.PerformedBy})");
                    }
                }
                
                ConsoleHelper.WaitForKeyPress();
            }
            catch (Exception ex)
            {
                ConsoleHelper.DisplayError($"Error viewing incident details: {ex.Message}");
                _logService.LogError($"Error viewing incident details: {ex.Message}");
                ConsoleHelper.WaitForKeyPress();
            }
        }
    }
}
