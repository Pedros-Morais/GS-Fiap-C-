using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BlackoutGuard.Models;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for managing system alerts
    /// </summary>
    public class AlertService
    {
        private readonly DataService _dataService;
        private readonly LogService _logService;

        public AlertService(DataService dataService, LogService logService)
        {
            _dataService = dataService ?? throw new ArgumentNullException(nameof(dataService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
        }

        /// <summary>
        /// Creates a new alert
        /// </summary>
        public async Task<Alert> CreateAlertAsync(string title, string message, AlertPriority priority, AlertType type)
        {
            return await CreateAlertAsync(title, message, priority, type, null, null, null);
        }
        
        /// <summary>
        /// Creates a new alert with additional metadata
        /// </summary>
        public async Task<Alert> CreateAlertAsync(string title, string message, AlertPriority priority, AlertType type, string source, Guid? relatedEntityId, string relatedEntityType)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(title))
                    throw new ArgumentException("Alert title cannot be empty", nameof(title));
                
                if (string.IsNullOrWhiteSpace(message))
                    throw new ArgumentException("Alert message cannot be empty", nameof(message));
                
                var alert = new Alert(title, message, priority, type);
                
                // Set additional metadata if provided
                if (!string.IsNullOrWhiteSpace(source))
                    alert.Source = source;
                    
                if (relatedEntityId.HasValue)
                {
                    if (relatedEntityType == "Incident")
                        alert.RelatedIncidentId = relatedEntityId;
                    else if (relatedEntityType == "Threat")
                        alert.RelatedThreatId = relatedEntityId;
                    else if (relatedEntityType == "Vulnerability")
                        alert.RelatedVulnerabilityId = relatedEntityId;
                }
                
                await _dataService.SaveAlertAsync(alert);
                
                _logService.LogInfo($"Created new alert: {title} with priority {priority}");
                return alert;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a new alert related to a specific entity
        /// </summary>
        public async Task<Alert> CreateRelatedAlertAsync(string title, string message, AlertPriority priority, 
                                                        AlertType type, Guid relatedEntityId, string relatedEntityType)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(title))
                    throw new ArgumentException("Alert title cannot be empty", nameof(title));
                
                if (string.IsNullOrWhiteSpace(message))
                    throw new ArgumentException("Alert message cannot be empty", nameof(message));
                
                if (string.IsNullOrWhiteSpace(relatedEntityType))
                    throw new ArgumentException("Related entity type cannot be empty", nameof(relatedEntityType));
                
                var alert = new Alert(title, message, priority, type, relatedEntityId, relatedEntityType);
                await _dataService.SaveAlertAsync(alert);
                
                _logService.LogInfo($"Created new {relatedEntityType}-related alert: {title} with priority {priority}");
                return alert;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating related alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a threat-related alert
        /// </summary>
        public async Task<Alert> CreateThreatAlertAsync(Threat threat)
        {
            try
            {
                if (threat == null)
                    throw new ArgumentNullException(nameof(threat));
                
                // Map threat severity to alert priority
                var priority = threat.Severity switch
                {
                    ThreatSeverity.Critical => AlertPriority.Critical,
                    ThreatSeverity.High => AlertPriority.High,
                    ThreatSeverity.Medium => AlertPriority.Medium,
                    _ => AlertPriority.Low
                };
                
                var title = $"Security Threat: {threat.Name}";
                var message = $"New security threat detected.\nSeverity: {threat.Severity}\nType: {threat.Type}\nDescription: {threat.Description}";
                
                return await CreateRelatedAlertAsync(title, message, priority, AlertType.ThreatDetected, threat.Id, "Threat");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating threat alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates an incident-related alert
        /// </summary>
        public async Task<Alert> CreateIncidentAlertAsync(Incident incident)
        {
            try
            {
                if (incident == null)
                    throw new ArgumentNullException(nameof(incident));
                
                // Map incident severity to alert priority
                var priority = incident.Severity switch
                {
                    IncidentSeverity.Critical => AlertPriority.Critical,
                    IncidentSeverity.High => AlertPriority.High,
                    IncidentSeverity.Medium => AlertPriority.Medium,
                    _ => AlertPriority.Low
                };
                
                var title = $"New Incident: {incident.Title}";
                var message = $"New incident reported.\nSeverity: {incident.Severity}\nType: {incident.Type}\nLocation: {incident.Location}\nDescription: {incident.Description}";
                
                return await CreateRelatedAlertAsync(title, message, priority, AlertType.IncidentReported, incident.Id, "Incident");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating incident alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a vulnerability-related alert
        /// </summary>
        public async Task<Alert> CreateVulnerabilityAlertAsync(Vulnerability vulnerability)
        {
            try
            {
                if (vulnerability == null)
                    throw new ArgumentNullException(nameof(vulnerability));
                
                // Map vulnerability severity to alert priority
                var priority = vulnerability.Severity switch
                {
                    VulnerabilitySeverity.Critical => AlertPriority.Critical,
                    VulnerabilitySeverity.High => AlertPriority.High,
                    VulnerabilitySeverity.Medium => AlertPriority.Medium,
                    _ => AlertPriority.Low
                };
                
                var title = $"New Vulnerability: {vulnerability.Name}";
                var message = $"New vulnerability discovered.\nSeverity: {vulnerability.Severity}\nType: {vulnerability.Type}\nAffected System: {vulnerability.AffectedSystem}\nDescription: {vulnerability.Description}";
                
                return await CreateRelatedAlertAsync(title, message, priority, AlertType.VulnerabilityFound, vulnerability.Id, "Vulnerability");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating vulnerability alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets all alerts
        /// </summary>
        public async Task<List<Alert>> GetAllAlertsAsync()
        {
            try
            {
                return await _dataService.GetAllAlertsAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all alerts: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets unread alerts
        /// </summary>
        public async Task<List<Alert>> GetUnreadAlertsAsync()
        {
            try
            {
                return await _dataService.GetUnreadAlertsAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting unread alerts: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets unacknowledged alerts
        /// </summary>
        public async Task<List<Alert>> GetUnacknowledgedAlertsAsync()
        {
            try
            {
                var alerts = await _dataService.GetAllAlertsAsync();
                return alerts.Where(a => a.Acknowledged == false).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting unacknowledged alerts: {ex.Message}");
                throw;
            }
        }
        
        /// <summary>
        /// Gets high priority alerts
        /// </summary>
        public async Task<List<Alert>> GetHighPriorityAlertsAsync()
        {
            try
            {
                var alerts = await _dataService.GetAllAlertsAsync();
                return alerts.Where(a => a.Priority == AlertPriority.High || a.Priority == AlertPriority.Critical).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting high priority alerts: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets alerts by type
        /// </summary>
        public async Task<List<Alert>> GetAlertsByTypeAsync(AlertType type)
        {
            try
            {
                var alerts = await _dataService.GetAllAlertsAsync();
                return alerts.Where(a => a.Type == type).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting alerts by type: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets an alert by ID
        /// </summary>
        public async Task<Alert?> GetAlertByIdAsync(Guid id)
        {
            try
            {
                return await _dataService.GetAlertByIdAsync(id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting alert by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Marks an alert as read
        /// </summary>
        public async Task MarkAlertAsReadAsync(Guid id, string readBy)
        {
            try
            {
                var alert = await _dataService.GetAlertByIdAsync(id);
                if (alert == null)
                {
                    throw new InvalidOperationException($"Alert with ID {id} not found");
                }
                
                alert.MarkAsRead(readBy);
                await _dataService.UpdateAlertAsync(alert);
                
                _logService.LogInfo($"Alert marked as read: {alert.Title} by {readBy}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error marking alert as read: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Acknowledges an alert
        /// </summary>
        public async Task AcknowledgeAlertAsync(Guid id, string acknowledgedBy, string comments = "")
        {
            try
            {
                var alert = await _dataService.GetAlertByIdAsync(id);
                if (alert == null)
                {
                    throw new InvalidOperationException($"Alert with ID {id} not found");
                }
                
                alert.Acknowledge(acknowledgedBy);
                alert.AcknowledgementComments = comments;
                await _dataService.UpdateAlertAsync(alert);
                
                _logService.LogInfo($"Alert acknowledged: {alert.Title} by {acknowledgedBy}");
                if (!string.IsNullOrWhiteSpace(comments))
                {
                    _logService.LogInfo($"Acknowledgement comments: {comments}");
                }
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error acknowledging alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes an alert
        /// </summary>
        public async Task DeleteAlertAsync(Guid id)
        {
            try
            {
                await _dataService.DeleteAlertAsync(id);
                _logService.LogInfo($"Alert deleted with ID: {id}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting alert: {ex.Message}");
                throw;
            }
        }
    }
}
