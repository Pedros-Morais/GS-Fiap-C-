using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BlackoutGuard.Models;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for managing security threats
    /// </summary>
    public class ThreatService
    {
        private readonly DataService _dataService;
        private readonly LogService _logService;
        private readonly AlertService _alertService;

        public ThreatService(DataService dataService, LogService logService, AlertService alertService)
        {
            _dataService = dataService ?? throw new ArgumentNullException(nameof(dataService));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            _alertService = alertService ?? throw new ArgumentNullException(nameof(alertService));
        }

        /// <summary>
        /// Creates a new security threat
        /// </summary>
        public async Task<Threat> CreateThreatAsync(string name, string description, ThreatSeverity severity, 
                                                  ThreatType type, string source, string target, string reportedBy)
        {
            try
            {
                // Validate inputs
                if (string.IsNullOrWhiteSpace(name))
                    throw new ArgumentException("Threat name cannot be empty", nameof(name));
                
                if (string.IsNullOrWhiteSpace(description))
                    throw new ArgumentException("Threat description cannot be empty", nameof(description));
                
                if (string.IsNullOrWhiteSpace(source))
                    throw new ArgumentException("Threat source cannot be empty", nameof(source));
                
                if (string.IsNullOrWhiteSpace(target))
                    throw new ArgumentException("Threat target cannot be empty", nameof(target));
                
                if (string.IsNullOrWhiteSpace(reportedBy))
                    throw new ArgumentException("Reporter cannot be empty", nameof(reportedBy));
                
                // Create the threat
                var threat = new Threat(name, description, severity, type, source, target, reportedBy);
                
                // Add recommended actions based on threat type and severity
                threat.RecommendedActions = GenerateRecommendedActions(threat);
                
                // Add potential impact based on severity and target
                threat.PotentialImpact = GeneratePotentialImpact(threat);
                
                // Save the threat
                await _dataService.SaveThreatAsync(threat);
                _logService.LogSecurity($"New security threat created: {name} with severity {severity}");
                
                // Generate an alert for the threat
                await _alertService.CreateThreatAlertAsync(threat);
                
                return threat;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error creating threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets all threats
        /// </summary>
        public async Task<List<Threat>> GetAllThreatsAsync()
        {
            try
            {
                return await _dataService.GetAllThreatsAsync();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all threats: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets a threat by ID
        /// </summary>
        public async Task<Threat?> GetThreatByIdAsync(Guid id)
        {
            try
            {
                return await _dataService.GetThreatByIdAsync(id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting threat by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets active threats
        /// </summary>
        public async Task<List<Threat>> GetActiveThreatsAsync()
        {
            try
            {
                var threats = await _dataService.GetAllThreatsAsync();
                return threats.Where(t => t.Status == ThreatStatus.Active || t.Status == ThreatStatus.Mitigated).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting active threats: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets high severity threats
        /// </summary>
        public async Task<List<Threat>> GetHighSeverityThreatsAsync()
        {
            try
            {
                var threats = await _dataService.GetAllThreatsAsync();
                return threats.Where(t => t.Severity == ThreatSeverity.High || t.Severity == ThreatSeverity.Critical).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting high severity threats: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets threats by type
        /// </summary>
        public async Task<List<Threat>> GetThreatsByTypeAsync(ThreatType type)
        {
            try
            {
                var threats = await _dataService.GetAllThreatsAsync();
                return threats.Where(t => t.Type == type).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting threats by type: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Adds an action to a threat
        /// </summary>
        public async Task AddThreatActionAsync(Guid id, string description, string performedBy)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(description))
                    throw new ArgumentException("Action description cannot be empty", nameof(description));
                
                if (string.IsNullOrWhiteSpace(performedBy))
                    throw new ArgumentException("Performer cannot be empty", nameof(performedBy));
                
                var threat = await _dataService.GetThreatByIdAsync(id);
                if (threat == null)
                {
                    throw new InvalidOperationException($"Threat with ID {id} not found");
                }
                
                threat.AddAction(description, performedBy);
                await _dataService.UpdateThreatAsync(threat);
                
                _logService.LogInfo($"Action added to threat {threat.Name}: {description} by {performedBy}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error adding threat action: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates a threat's status
        /// </summary>
        public async Task UpdateThreatStatusAsync(Guid id, ThreatStatus newStatus, string performedBy)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(performedBy))
                    throw new ArgumentException("Performer cannot be empty", nameof(performedBy));
                
                var threat = await _dataService.GetThreatByIdAsync(id);
                if (threat == null)
                {
                    throw new InvalidOperationException($"Threat with ID {id} not found");
                }
                
                var oldStatus = threat.Status;
                threat.Status = newStatus;
                
                // Add an action for the status change
                threat.AddAction($"Status changed from {oldStatus} to {newStatus}", performedBy);
                
                // If the threat is being resolved, record who resolved it
                if (newStatus == ThreatStatus.Resolved)
                {
                    threat.Resolve(performedBy);
                }
                
                await _dataService.UpdateThreatAsync(threat);
                
                _logService.LogInfo($"Threat {threat.Name} status updated from {oldStatus} to {newStatus} by {performedBy}");
                
                // Create an alert for status change if it's an important change
                if (threat.Severity >= ThreatSeverity.High && 
                    (newStatus == ThreatStatus.Resolved || newStatus == ThreatStatus.Mitigated))
                {
                    var priority = threat.Severity == ThreatSeverity.Critical ? AlertPriority.High : AlertPriority.Medium;
                    await _alertService.CreateRelatedAlertAsync(
                        $"Threat Status Update: {threat.Name}",
                        $"The status of threat '{threat.Name}' has been changed from {oldStatus} to {newStatus} by {performedBy}.",
                        priority,
                        AlertType.SystemStatus,
                        threat.Id,
                        "Threat"
                    );
                }
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating threat status: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates a threat
        /// </summary>
        public async Task UpdateThreatAsync(Threat threat)
        {
            try
            {
                if (threat == null)
                    throw new ArgumentNullException(nameof(threat));
                
                await _dataService.UpdateThreatAsync(threat);
                _logService.LogInfo($"Threat updated: {threat.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes a threat
        /// </summary>
        public async Task DeleteThreatAsync(Guid id)
        {
            try
            {
                await _dataService.DeleteThreatAsync(id);
                _logService.LogInfo($"Threat deleted with ID: {id}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Generates recommended actions based on threat type and severity
        /// </summary>
        private string GenerateRecommendedActions(Threat threat)
        {
            var recommendations = new List<string>();
            
            // Basic recommendations based on severity
            switch (threat.Severity)
            {
                case ThreatSeverity.Critical:
                    recommendations.Add("Activate emergency response team immediately");
                    recommendations.Add("Isolate affected systems from the network");
                    recommendations.Add("Notify executive management and security teams");
                    break;
                    
                case ThreatSeverity.High:
                    recommendations.Add("Escalate to security response team");
                    recommendations.Add("Monitor affected systems closely");
                    recommendations.Add("Prepare for potential isolation of systems");
                    break;
                    
                case ThreatSeverity.Medium:
                    recommendations.Add("Investigate the threat further");
                    recommendations.Add("Increase monitoring of affected systems");
                    recommendations.Add("Prepare mitigation strategies");
                    break;
                    
                case ThreatSeverity.Low:
                    recommendations.Add("Monitor the situation");
                    recommendations.Add("Document findings for future reference");
                    recommendations.Add("Review security controls");
                    break;
            }
            
            // Additional recommendations based on threat type
            switch (threat.Type)
            {
                case ThreatType.Malware:
                    recommendations.Add("Run full system scans with updated antivirus");
                    recommendations.Add("Check for unusual processes or connections");
                    recommendations.Add("Update malware definitions and security patches");
                    break;
                    
                case ThreatType.Phishing:
                    recommendations.Add("Alert users about the phishing attempt");
                    recommendations.Add("Block sender domains and email addresses");
                    recommendations.Add("Verify if any credentials were compromised");
                    break;
                    
                case ThreatType.DDoS:
                    recommendations.Add("Activate DDoS mitigation services");
                    recommendations.Add("Increase bandwidth or implement rate limiting");
                    recommendations.Add("Contact upstream providers for assistance");
                    break;
                    
                case ThreatType.Intrusion:
                    recommendations.Add("Review access logs for unauthorized entries");
                    recommendations.Add("Change affected credentials and access keys");
                    recommendations.Add("Strengthen access controls and authentication");
                    break;
                    
                case ThreatType.DataBreach:
                    recommendations.Add("Identify the scope of compromised data");
                    recommendations.Add("Prepare for potential disclosure requirements");
                    recommendations.Add("Secure remaining data and close access points");
                    break;
                    
                case ThreatType.InsiderThreat:
                    recommendations.Add("Review access logs and user activity");
                    recommendations.Add("Temporarily restrict privileged access");
                    recommendations.Add("Coordinate with HR and legal departments");
                    break;
                    
                case ThreatType.ConfigurationError:
                    recommendations.Add("Audit system configurations");
                    recommendations.Add("Revert to known good configurations");
                    recommendations.Add("Implement configuration management controls");
                    break;
                    
                case ThreatType.ZeroDay:
                    recommendations.Add("Implement additional monitoring for exploit indicators");
                    recommendations.Add("Contact vendor for emergency patches");
                    recommendations.Add("Consider alternative controls or isolation");
                    break;
                    
                case ThreatType.RansomwareAttack:
                    recommendations.Add("Isolate affected systems immediately");
                    recommendations.Add("Check backup integrity and prepare for restoration");
                    recommendations.Add("Do not pay ransom without consulting security experts");
                    break;
                    
                case ThreatType.Other:
                    recommendations.Add("Conduct detailed analysis of the threat");
                    recommendations.Add("Consult with security experts");
                    recommendations.Add("Document unique characteristics for future reference");
                    break;
            }
            
            return string.Join("\n", recommendations);
        }

        /// <summary>
        /// Generates potential impact description based on threat severity and target
        /// </summary>
        private string GeneratePotentialImpact(Threat threat)
        {
            var impacts = new List<string>();
            
            // Base impacts on severity
            switch (threat.Severity)
            {
                case ThreatSeverity.Critical:
                    impacts.Add("Potential for widespread power outages affecting critical infrastructure");
                    impacts.Add("Risk of cascading failures across interconnected grid systems");
                    impacts.Add("Possible extended downtime requiring emergency measures");
                    break;
                    
                case ThreatSeverity.High:
                    impacts.Add("Localized power disruptions possible");
                    impacts.Add("Compromise of key grid control systems");
                    impacts.Add("Potential data exfiltration of sensitive operational information");
                    break;
                    
                case ThreatSeverity.Medium:
                    impacts.Add("Degraded system performance and reliability");
                    impacts.Add("Limited access to operational systems");
                    impacts.Add("Increased vulnerability to secondary attacks");
                    break;
                    
                case ThreatSeverity.Low:
                    impacts.Add("Minimal immediate operational impact");
                    impacts.Add("Potential intelligence gathering by threat actors");
                    impacts.Add("Minor disruptions to non-critical systems");
                    break;
            }
            
            // Add target-specific impacts
            if (threat.Target.Contains("SCADA", StringComparison.OrdinalIgnoreCase) || 
                threat.Target.Contains("control", StringComparison.OrdinalIgnoreCase))
            {
                impacts.Add("Loss of visibility and control over power distribution systems");
                impacts.Add("Potential for manipulated commands sent to field devices");
            }
            
            if (threat.Target.Contains("database", StringComparison.OrdinalIgnoreCase) || 
                threat.Target.Contains("data", StringComparison.OrdinalIgnoreCase))
            {
                impacts.Add("Compromise of sensitive customer or operational data");
                impacts.Add("Regulatory compliance violations and potential fines");
            }
            
            if (threat.Target.Contains("network", StringComparison.OrdinalIgnoreCase) || 
                threat.Target.Contains("communication", StringComparison.OrdinalIgnoreCase))
            {
                impacts.Add("Disruption of critical communications between control centers and substations");
                impacts.Add("Inability to monitor and respond to grid conditions in real-time");
            }
            
            if (threat.Target.Contains("substation", StringComparison.OrdinalIgnoreCase) || 
                threat.Target.Contains("generator", StringComparison.OrdinalIgnoreCase))
            {
                impacts.Add("Physical damage to critical power generation or transmission equipment");
                impacts.Add("Extended restoration time due to specialized equipment requirements");
            }
            
            return string.Join("\n", impacts);
        }
    }
}
