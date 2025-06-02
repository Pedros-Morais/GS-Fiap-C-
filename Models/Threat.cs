using System;
using System.Collections.Generic;

namespace BlackoutGuard.Models
{
    /// <summary>
    /// Represents a cybersecurity threat detected in the power grid system
    /// </summary>
    public class Threat
    {
        // Unique identifier for the threat
        public Guid Id { get; private set; }
        
        // Name/title of the threat
        public string Name { get; set; }
        
        // Detailed description of the threat
        public string Description { get; set; }
        
        // Severity level of the threat
        public ThreatSeverity Severity { get; set; }
        
        // Type/category of the threat
        public ThreatType Type { get; set; }
        
        // When the threat was first detected
        public DateTime DetectedAt { get; private set; }
        
        // Source IP address or identifier where the threat originated
        public string Source { get; set; }
        
        // Target system or component that was threatened
        public string Target { get; set; }
        
        // Current status of the threat
        public ThreatStatus Status { get; set; }
        
        // List of actions taken to address the threat
        public List<ThreatAction> Actions { get; set; }
        
        // Potential impact if the threat is successful
        public string PotentialImpact { get; set; }
        
        // Recommended mitigation steps
        public string RecommendedActions { get; set; }
        
        // User who detected or reported the threat
        public string ReportedBy { get; set; }
        
        // User who resolved the threat (if applicable)
        public string ResolvedBy { get; set; }
        
        // When the threat was resolved (if applicable)
        public DateTime? ResolvedAt { get; set; }

        // Default constructor for deserialization
        public Threat()
        {
            Id = Guid.NewGuid();
            DetectedAt = DateTime.UtcNow;
            Status = ThreatStatus.Active;
            Actions = new List<ThreatAction>();
        }

        // Constructor with required fields
        public Threat(string name, string description, ThreatSeverity severity, ThreatType type, 
                     string source, string target, string reportedBy)
        {
            Id = Guid.NewGuid();
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Description = description ?? throw new ArgumentNullException(nameof(description));
            Severity = severity;
            Type = type;
            DetectedAt = DateTime.UtcNow;
            Source = source;
            Target = target;
            Status = ThreatStatus.Active;
            ReportedBy = reportedBy;
            Actions = new List<ThreatAction>();
        }

        /// <summary>
        /// Adds a new action taken to address the threat
        /// </summary>
        public void AddAction(string description, string performedBy)
        {
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentException("Action description cannot be empty", nameof(description));
            
            if (string.IsNullOrWhiteSpace(performedBy))
                throw new ArgumentException("Action performer cannot be empty", nameof(performedBy));
                
            Actions.Add(new ThreatAction
            {
                Description = description,
                PerformedBy = performedBy,
                PerformedAt = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Resolves the threat and records who resolved it
        /// </summary>
        public void Resolve(string resolvedBy)
        {
            if (string.IsNullOrWhiteSpace(resolvedBy))
                throw new ArgumentException("Resolver cannot be empty", nameof(resolvedBy));
                
            Status = ThreatStatus.Resolved;
            ResolvedBy = resolvedBy;
            ResolvedAt = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Represents an action taken to address a threat
    /// </summary>
    public class ThreatAction
    {
        // Description of the action taken
        public string Description { get; set; }
        
        // User who performed the action
        public string PerformedBy { get; set; }
        
        // When the action was performed
        public DateTime PerformedAt { get; set; }
    }

    /// <summary>
    /// Represents the severity level of a threat
    /// </summary>
    public enum ThreatSeverity
    {
        Low,       // Minimal potential impact
        Medium,    // Moderate potential impact
        High,      // Significant potential impact
        Critical   // Severe potential impact, immediate action required
    }

    /// <summary>
    /// Represents the category of a threat
    /// </summary>
    public enum ThreatType
    {
        Malware,           // Malicious software detected
        Phishing,          // Social engineering attempts
        DDoS,              // Distributed Denial of Service
        Intrusion,         // Unauthorized access
        DataBreach,        // Data theft or exposure
        InsiderThreat,     // Threat from within the organization
        ConfigurationError, // Security misconfigurations
        ZeroDay,           // Previously unknown vulnerability
        RansomwareAttack,  // Ransomware attack
        Other              // Other types of threats
    }

    /// <summary>
    /// Represents the current status of a threat
    /// </summary>
    public enum ThreatStatus
    {
        Active,    // Threat is currently active
        Mitigated, // Threat has been mitigated but not fully resolved
        Resolved,  // Threat has been completely resolved
        FalseAlarm // Determined to be a false alarm
    }
}
