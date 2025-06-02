using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BlackoutGuard.Models;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for managing power grid incidents
    /// </summary>
    public class IncidentService
    {
        private readonly DataService _dataService;
        private readonly LogService _logService;
        private readonly AlertService _alertService;

        public IncidentService(DataService dataService, LogService logService, AlertService alertService)
        {
            _dataService = dataService ?? throw new ArgumentNullException(nameof(dataService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _alertService = alertService ?? throw new ArgumentNullException(nameof(alertService));
        }

        /// <summary>
        /// Creates a new incident
        /// </summary>
        public async Task<Incident> CreateIncidentAsync(string title, string description, DateTime occurredAt,
                                                      IncidentSeverity severity, IncidentType type, 
                                                      string location, string reportedBy)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(title))
                    throw new ArgumentException("Incident title cannot be empty", nameof(title));
                
                if (string.IsNullOrWhiteSpace(description))
                    throw new ArgumentException("Incident description cannot be empty", nameof(description));
                
                if (occurredAt > DateTime.UtcNow)
                    throw new ArgumentException("Incident occurrence time cannot be in the future", nameof(occurredAt));
                
                if (string.IsNullOrWhiteSpace(location))
                    throw new ArgumentException("Incident location cannot be empty", nameof(location));
                
                if (string.IsNullOrWhiteSpace(reportedBy))
                    throw new ArgumentException("Reporter cannot be empty", nameof(reportedBy));
                
                // Create the incident
                var incident = new Incident(title, description, occurredAt, severity, type, location, reportedBy);
                
                // Estimate duration based on severity and type
                incident.EstimatedDuration = EstimateIncidentDuration(severity, type);
                
                // Estimate affected users based on location and severity
                incident.AffectedUsers = EstimateAffectedUsers(location, severity);
                
                // Save the incident
                await _dataService.SaveIncidentAsync(incident);
                _logService.LogInfo($"New incident created: {title} with severity {severity}");
                
                // Generate an alert for the incident
                await _alertService.CreateIncidentAlertAsync(incident);
                
                return incident;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a new incident related to a security threat
        /// </summary>
        public async Task<Incident> CreateThreatRelatedIncidentAsync(string title, string description, DateTime occurredAt,
                                                                   IncidentSeverity severity, IncidentType type,
                                                                   string location, string reportedBy, Guid threatId)
        {
            try
            {
                var incident = await CreateIncidentAsync(title, description, occurredAt, severity, type, location, reportedBy);
                
                // Set the related threat ID
                incident.RelatedThreatId = threatId;
                await _dataService.UpdateIncidentAsync(incident);
                
                _logService.LogInfo($"Incident linked to threat ID {threatId}");
                return incident;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating threat-related incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets all incidents
        /// </summary>
        public async Task<List<Incident>> GetAllIncidentsAsync()
        {
            try
            {
                return await _dataService.GetAllIncidentsAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all incidents: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets an incident by ID
        /// </summary>
        public async Task<Incident?> GetIncidentByIdAsync(Guid id)
        {
            try
            {
                return await _dataService.GetIncidentByIdAsync(id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting incident by ID: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Finds an incident by a partial ID string (prefix matching)
        /// </summary>
        public async Task<Incident?> FindIncidentByPartialIdAsync(string partialId)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(partialId))
                    return null;
                    
                // If it's a full valid GUID, use the direct method
                if (Guid.TryParse(partialId, out Guid fullId))
                    return await GetIncidentByIdAsync(fullId);
                
                // Otherwise search by prefix
                var allIncidents = await GetAllIncidentsAsync();
                var matchingIncident = allIncidents.FirstOrDefault(i => 
                    i.Id.ToString().StartsWith(partialId, StringComparison.OrdinalIgnoreCase));
                    
                return matchingIncident;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error finding incident by partial ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets open incidents
        /// </summary>
        public async Task<List<Incident>> GetOpenIncidentsAsync()
        {
            try
            {
                var incidents = await _dataService.GetAllIncidentsAsync();
                return incidents.Where(i => i.Status == IncidentStatus.Open || 
                                         i.Status == IncidentStatus.InProgress || 
                                         i.Status == IncidentStatus.Pending).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting open incidents: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets high severity incidents
        /// </summary>
        public async Task<List<Incident>> GetHighSeverityIncidentsAsync()
        {
            try
            {
                var incidents = await _dataService.GetAllIncidentsAsync();
                return incidents.Where(i => i.Severity == IncidentSeverity.High || 
                                         i.Severity == IncidentSeverity.Critical).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting high severity incidents: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets incidents by type
        /// </summary>
        public async Task<List<Incident>> GetIncidentsByTypeAsync(IncidentType type)
        {
            try
            {
                var incidents = await _dataService.GetAllIncidentsAsync();
                return incidents.Where(i => i.Type == type).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting incidents by type: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets incidents by location
        /// </summary>
        public async Task<List<Incident>> GetIncidentsByLocationAsync(string location)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(location))
                    throw new ArgumentException("Location cannot be empty", nameof(location));
                
                var incidents = await _dataService.GetAllIncidentsAsync();
                return incidents.Where(i => i.Location.Contains(location, StringComparison.OrdinalIgnoreCase)).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting incidents by location: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets incidents by date range
        /// </summary>
        public async Task<List<Incident>> GetIncidentsByDateRangeAsync(DateTime startDate, DateTime endDate)
        {
            try
            {
                if (startDate > endDate)
                    throw new ArgumentException("Start date must be before end date");
                
                var incidents = await _dataService.GetAllIncidentsAsync();
                return incidents.Where(i => i.OccurredAt >= startDate && i.OccurredAt <= endDate).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting incidents by date range: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Adds an action to an incident
        /// </summary>
        public async Task AddIncidentActionAsync(Guid id, string description, string performedBy)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(description))
                    throw new ArgumentException("Action description cannot be empty", nameof(description));
                
                if (string.IsNullOrWhiteSpace(performedBy))
                    throw new ArgumentException("Performer cannot be empty", nameof(performedBy));
                
                var incident = await _dataService.GetIncidentByIdAsync(id);
                if (incident == null)
                {
                    throw new InvalidOperationException($"Incident with ID {id} not found");
                }
                
                incident.AddAction(description, performedBy);
                await _dataService.UpdateIncidentAsync(incident);
                
                _logService.LogInfo($"Action added to incident {incident.Title}: {description} by {performedBy}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error adding incident action: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Assigns an incident to a user
        /// </summary>
        public async Task AssignIncidentAsync(Guid id, string assignedTo)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(assignedTo))
                    throw new ArgumentException("Assignee cannot be empty", nameof(assignedTo));
                
                var incident = await _dataService.GetIncidentByIdAsync(id);
                if (incident == null)
                {
                    throw new InvalidOperationException($"Incident with ID {id} not found");
                }
                
                incident.Assign(assignedTo);
                await _dataService.UpdateIncidentAsync(incident);
                
                _logService.LogInfo($"Incident {incident.Title} assigned to {assignedTo}");
                
                // Create an alert for assignment if it's a high severity incident
                if (incident.Severity >= IncidentSeverity.High)
                {
                    var priority = incident.Severity == IncidentSeverity.Critical ? AlertPriority.High : AlertPriority.Medium;
                    await _alertService.CreateRelatedAlertAsync(
                        $"Incident Assigned: {incident.Title}",
                        $"The incident '{incident.Title}' has been assigned to {assignedTo}.",
                        priority,
                        AlertType.SystemStatus,
                        incident.Id,
                        "Incident"
                    );
                }
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error assigning incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an incident's status
        /// </summary>
        public async Task UpdateIncidentStatusAsync(Guid id, IncidentStatus newStatus, string performedBy)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(performedBy))
                    throw new ArgumentException("Performer cannot be empty", nameof(performedBy));
                
                var incident = await _dataService.GetIncidentByIdAsync(id);
                if (incident == null)
                {
                    throw new InvalidOperationException($"Incident with ID {id} not found");
                }
                
                var oldStatus = incident.Status;
                incident.Status = newStatus;
                
                // Add an action for the status change
                incident.AddAction($"Status changed from {oldStatus} to {newStatus}", performedBy);
                
                await _dataService.UpdateIncidentAsync(incident);
                
                _logService.LogInfo($"Incident {incident.Title} status updated from {oldStatus} to {newStatus} by {performedBy}");
                
                // Create an alert for status change if it's a high severity incident
                if (incident.Severity >= IncidentSeverity.High && newStatus == IncidentStatus.Resolved)
                {
                    var priority = incident.Severity == IncidentSeverity.Critical ? AlertPriority.High : AlertPriority.Medium;
                    await _alertService.CreateRelatedAlertAsync(
                        $"Incident Status Update: {incident.Title}",
                        $"The status of incident '{incident.Title}' has been changed from {oldStatus} to {newStatus} by {performedBy}.",
                        priority,
                        AlertType.SystemStatus,
                        incident.Id,
                        "Incident"
                    );
                }
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating incident status: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Resolves an incident
        /// </summary>
        public async Task ResolveIncidentAsync(Guid id, string resolvedBy, string rootCause, int actualDuration)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(resolvedBy))
                    throw new ArgumentException("Resolver cannot be empty", nameof(resolvedBy));
                
                if (string.IsNullOrWhiteSpace(rootCause))
                    throw new ArgumentException("Root cause cannot be empty", nameof(rootCause));
                
                if (actualDuration <= 0)
                    throw new ArgumentException("Actual duration must be positive", nameof(actualDuration));
                
                var incident = await _dataService.GetIncidentByIdAsync(id);
                if (incident == null)
                {
                    throw new InvalidOperationException($"Incident with ID {id} not found");
                }
                
                incident.Resolve(resolvedBy, rootCause, actualDuration);
                await _dataService.UpdateIncidentAsync(incident);
                
                _logService.LogInfo($"Incident {incident.Title} resolved by {resolvedBy}");
                
                // Create an alert for the resolution
                var priority = incident.Severity >= IncidentSeverity.High ? AlertPriority.Medium : AlertPriority.Low;
                await _alertService.CreateRelatedAlertAsync(
                    $"Incident Resolved: {incident.Title}",
                    $"The incident '{incident.Title}' has been resolved by {resolvedBy}.\nRoot cause: {rootCause}\nActual duration: {actualDuration} minutes.",
                    priority,
                    AlertType.SystemStatus,
                    incident.Id,
                    "Incident"
                );
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error resolving incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an incident
        /// </summary>
        public async Task UpdateIncidentAsync(Incident incident)
        {
            try
            {
                if (incident == null)
                    throw new ArgumentNullException(nameof(incident));
                
                await _dataService.UpdateIncidentAsync(incident);
                _logService.LogInfo($"Incident updated: {incident.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes an incident
        /// </summary>
        public async Task DeleteIncidentAsync(Guid id)
        {
            try
            {
                await _dataService.DeleteIncidentAsync(id);
                _logService.LogInfo($"Incident deleted with ID: {id}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting incident: {ex.Message}");
                throw;
            }
        }

        #region Helper Methods

        /// <summary>
        /// Estimates incident duration based on severity and type
        /// </summary>
        private int EstimateIncidentDuration(IncidentSeverity severity, IncidentType type)
        {
            // Base duration in minutes
            var baseDuration = severity switch
            {
                IncidentSeverity.Critical => 240,  // 4 hours
                IncidentSeverity.High => 120,      // 2 hours
                IncidentSeverity.Medium => 60,     // 1 hour
                _ => 30                           // 30 minutes
            };
            
            // Adjust based on incident type
            var multiplier = type switch
            {
                IncidentType.PowerOutage => 2.0,
                IncidentType.CyberAttack => 1.8,
                IncidentType.EquipmentFailure => 1.5,
                IncidentType.PhysicalAttack => 2.0,
                IncidentType.NaturalDisaster => 2.5,
                _ => 1.0
            };
            
            return (int)(baseDuration * multiplier);
        }

        /// <summary>
        /// Estimates affected users based on location and severity
        /// </summary>
        private int EstimateAffectedUsers(string location, IncidentSeverity severity)
        {
            // Base affected users
            var baseAffected = severity switch
            {
                IncidentSeverity.Critical => 10000,
                IncidentSeverity.High => 5000,
                IncidentSeverity.Medium => 1000,
                _ => 100
            };
            
            // Adjust based on location keywords
            var multiplier = 1.0;
            
            if (location.Contains("urban", StringComparison.OrdinalIgnoreCase) || 
                location.Contains("city", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 2.5;
            }
            else if (location.Contains("suburban", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 1.5;
            }
            else if (location.Contains("rural", StringComparison.OrdinalIgnoreCase))
            {
                multiplier = 0.5;
            }
            
            if (location.Contains("substation", StringComparison.OrdinalIgnoreCase))
            {
                multiplier *= 1.2;
            }
            
            if (location.Contains("grid", StringComparison.OrdinalIgnoreCase) || 
                location.Contains("network", StringComparison.OrdinalIgnoreCase))
            {
                multiplier *= 1.5;
            }
            
            if (location.Contains("plant", StringComparison.OrdinalIgnoreCase) || 
                location.Contains("generation", StringComparison.OrdinalIgnoreCase))
            {
                multiplier *= 2.0;
            }
            
            return (int)(baseAffected * multiplier);
        }

        #endregion
    }
}
