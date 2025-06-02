using System;
using System.Collections.Generic;

namespace BlackoutGuard.Models
{
    /// <summary>
    /// Represents a power grid incident, which could be a security breach, outage, or other operational issue
    /// </summary>
    public class Incident
    {
        // Unique identifier for the incident
        public Guid Id { get; private set; }
        
        // Title/name of the incident
        public string Title { get; set; }
        
        // Detailed description of the incident
        public string Description { get; set; }
        
        // When the incident occurred or was first detected
        public DateTime OccurredAt { get; set; }
        
        // When the incident was reported to the system
        public DateTime ReportedAt { get; private set; }
        
        // Current status of the incident
        public IncidentStatus Status { get; set; }
        
        // Severity level of the incident
        public IncidentSeverity Severity { get; set; }
        
        // Type/category of the incident
        public IncidentType Type { get; set; }
        
        // Affected location or grid component
        public string Location { get; set; }
        
        // Estimated number of affected users/customers
        public int? AffectedUsers { get; set; }
        
        // Estimated duration of the incident (in minutes)
        public int? EstimatedDuration { get; set; }
        
        // Actual duration of the incident (in minutes), once resolved
        public int? ActualDuration { get; set; }
        
        // User who reported the incident
        public string ReportedBy { get; set; }
        
        // User who is assigned to handle the incident
        public string AssignedTo { get; set; }
        
        // User who resolved the incident (if applicable)
        public string ResolvedBy { get; set; }
        
        // When the incident was resolved (if applicable)
        public DateTime? ResolvedAt { get; set; }
        
        // Root cause analysis results
        public string RootCause { get; set; }
        
        // Associated threat ID, if this incident was caused by a security threat
        public Guid? RelatedThreatId { get; set; }
        
        // List of actions taken to address the incident
        public List<IncidentAction> Actions { get; set; }

        // Default constructor for deserialization
        public Incident()
        {
            Id = Guid.NewGuid();
            ReportedAt = DateTime.UtcNow;
            Status = IncidentStatus.Open;
            Actions = new List<IncidentAction>();
        }

        // Constructor with required fields
        public Incident(string title, string description, DateTime occurredAt, 
                       IncidentSeverity severity, IncidentType type, string location, string reportedBy)
        {
            Id = Guid.NewGuid();
            Title = title ?? throw new ArgumentNullException(nameof(title));
            Description = description ?? throw new ArgumentNullException(nameof(description));
            OccurredAt = occurredAt;
            ReportedAt = DateTime.UtcNow;
            Status = IncidentStatus.Open;
            Severity = severity;
            Type = type;
            Location = location ?? throw new ArgumentNullException(nameof(location));
            ReportedBy = reportedBy ?? throw new ArgumentNullException(nameof(reportedBy));
            Actions = new List<IncidentAction>();
        }

        /// <summary>
        /// Adds a new action taken to address the incident
        /// </summary>
        public void AddAction(string description, string performedBy)
        {
            if (string.IsNullOrWhiteSpace(description))
                throw new ArgumentException("Action description cannot be empty", nameof(description));
            
            if (string.IsNullOrWhiteSpace(performedBy))
                throw new ArgumentException("Action performer cannot be empty", nameof(performedBy));
                
            Actions.Add(new IncidentAction
            {
                Description = description,
                PerformedBy = performedBy,
                PerformedAt = DateTime.UtcNow
            });
        }

        /// <summary>
        /// Assigns the incident to a specific user
        /// </summary>
        public void Assign(string assignedTo)
        {
            if (string.IsNullOrWhiteSpace(assignedTo))
                throw new ArgumentException("Assignee cannot be empty", nameof(assignedTo));
                
            AssignedTo = assignedTo;
            Status = IncidentStatus.InProgress;
            AddAction($"Incident assigned to {assignedTo}", assignedTo);
        }

        /// <summary>
        /// Resolves the incident and records resolution details
        /// </summary>
        public void Resolve(string resolvedBy, string rootCause, int actualDuration)
        {
            if (string.IsNullOrWhiteSpace(resolvedBy))
                throw new ArgumentException("Resolver cannot be empty", nameof(resolvedBy));
            
            if (string.IsNullOrWhiteSpace(rootCause))
                throw new ArgumentException("Root cause cannot be empty", nameof(rootCause));
            
            if (actualDuration <= 0)
                throw new ArgumentException("Actual duration must be positive", nameof(actualDuration));
                
            Status = IncidentStatus.Resolved;
            ResolvedBy = resolvedBy;
            ResolvedAt = DateTime.UtcNow;
            RootCause = rootCause;
            ActualDuration = actualDuration;
            
            AddAction($"Incident resolved. Root cause: {rootCause}", resolvedBy);
        }
    }

    /// <summary>
    /// Represents an action taken to address an incident
    /// </summary>
    public class IncidentAction
    {
        // Description of the action taken
        public string Description { get; set; }
        
        // User who performed the action
        public string PerformedBy { get; set; }
        
        // When the action was performed
        public DateTime PerformedAt { get; set; }
        
        // Timestamp for UI compatibility
        public DateTime Timestamp => PerformedAt;
    }

    /// <summary>
    /// Represents the current status of an incident
    /// </summary>
    public enum IncidentStatus
    {
        Open,       // Newly reported, not yet assigned
        InProgress, // Being actively worked on
        Pending,    // Waiting for external action or information
        Resolved,   // Successfully resolved
        Closed      // Administratively closed without resolution
    }

    /// <summary>
    /// Represents the severity level of an incident
    /// </summary>
    public enum IncidentSeverity
    {
        Low,       // Minimal impact, no service disruption
        Medium,    // Limited impact, partial service disruption
        High,      // Significant impact, major service disruption
        Critical   // Catastrophic impact, complete service loss
    }

    /// <summary>
    /// Represents the category of an incident
    /// </summary>
    public enum IncidentType
    {
        PowerOutage,        // Complete power loss
        PartialOutage,      // Partial power loss or brownout
        SecurityBreach,     // Security violation or breach
        EquipmentFailure,   // Hardware or equipment failure
        NetworkIssue,       // Communication network problems
        SoftwareFailure,    // Control system software issues
        NaturalDisaster,    // Weather or natural events
        HumanError,         // Mistakes by personnel
        CyberAttack,        // Deliberate cyber attack
        PhysicalAttack,     // Physical attack on infrastructure
        UnplannedMaintenance // Sudden maintenance requirement
    }
}
