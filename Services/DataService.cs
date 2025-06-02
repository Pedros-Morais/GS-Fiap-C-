using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BlackoutGuard.Models;
using BlackoutGuard.Utils;

namespace BlackoutGuard.Services
{
    /// <summary>
    /// Service responsible for data persistence and retrieval
    /// </summary>
    public class DataService
    {
        private readonly string _dataDirectory;
        private readonly LogService _logService;
        
        private readonly string _usersFilePath;
        private readonly string _threatsFilePath;
        private readonly string _incidentsFilePath;
        private readonly string _vulnerabilitiesFilePath;
        private readonly string _alertsFilePath;
        
        private readonly JsonSerializerOptions _jsonOptions;

        public DataService(string dataDirectory, LogService logService)
        {
            _dataDirectory = dataDirectory ?? throw new ArgumentNullException(nameof(dataDirectory));
            _logService = logService ?? throw new ArgumentNullException(nameof(logService));
            
            // Create data directory if it doesn't exist
            if (!Directory.Exists(_dataDirectory))
            {
                Directory.CreateDirectory(_dataDirectory);
                _logService.LogInfo($"Created data directory: {_dataDirectory}");
            }
            
            // Initialize file paths
            _usersFilePath = Path.Combine(_dataDirectory, "users.json");
            _threatsFilePath = Path.Combine(_dataDirectory, "threats.json");
            _incidentsFilePath = Path.Combine(_dataDirectory, "incidents.json");
            _vulnerabilitiesFilePath = Path.Combine(_dataDirectory, "vulnerabilities.json");
            _alertsFilePath = Path.Combine(_dataDirectory, "alerts.json");
            
            // Configure JSON serialization options
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
            
            // Initialize the data files
            InitializeDataFiles();
        }

        /// <summary>
        /// Ensures all required data directories exist
        /// </summary>
        public void EnsureDataDirectoriesExist()
        {
            // Create subdirectories for various data types
            string[] subdirectories = {
                "Backups",
                "Exports",
                "Reports",
                "Temp"
            };
            
            foreach (var subdir in subdirectories)
            {
                string path = Path.Combine(_dataDirectory, subdir);
                if (!Directory.Exists(path))
                {
                    Directory.CreateDirectory(path);
                    _logService.LogInfo($"Created directory: {path}");
                }
            }
        }
        
        /// <summary>
        /// Initializes data files if they don't exist
        /// </summary>
        private void InitializeDataFiles()
        {
            try
            {
                InitializeFileIfNotExists(_usersFilePath, new List<User>());
                InitializeFileIfNotExists(_threatsFilePath, new List<Threat>());
                InitializeFileIfNotExists(_incidentsFilePath, new List<Incident>());
                InitializeFileIfNotExists(_vulnerabilitiesFilePath, new List<Vulnerability>());
                InitializeFileIfNotExists(_alertsFilePath, new List<Alert>());
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error initializing data files: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Initializes a specific file with default data if it doesn't exist
        /// </summary>
        private void InitializeFileIfNotExists<T>(string filePath, T defaultData)
        {
            if (!File.Exists(filePath))
            {
                var json = JsonSerializer.Serialize(defaultData, _jsonOptions);
                File.WriteAllText(filePath, json);
                _logService.LogInfo($"Initialized data file: {filePath}");
            }
        }

        #region User Operations

        /// <summary>
        /// Gets all users
        /// </summary>
        public async Task<List<User>> GetAllUsersAsync()
        {
            try
            {
                var json = await File.ReadAllTextAsync(_usersFilePath);
                var users = JsonSerializer.Deserialize<List<User>>(json, _jsonOptions) ?? new List<User>();
                return users;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all users: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets a user by ID
        /// </summary>
        public async Task<User?> GetUserByIdAsync(Guid id)
        {
            try
            {
                var users = await GetAllUsersAsync();
                return users.FirstOrDefault(u => u.Id == id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting user by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets a user by username
        /// </summary>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(username))
                    throw new ArgumentException("Username cannot be empty", nameof(username));
                
                var users = await GetAllUsersAsync();
                return users.FirstOrDefault(u => u.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting user by username: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves a new user
        /// </summary>
        public async Task SaveUserAsync(User user)
        {
            try
            {
                if (user == null)
                    throw new ArgumentNullException(nameof(user));
                
                var users = await GetAllUsersAsync();
                
                // Check if user with same ID already exists
                if (users.Any(u => u.Id == user.Id))
                {
                    throw new InvalidOperationException($"User with ID {user.Id} already exists");
                }
                
                // Check if username is already taken
                if (users.Any(u => u.Username.Equals(user.Username, StringComparison.OrdinalIgnoreCase)))
                {
                    throw new InvalidOperationException($"Username '{user.Username}' is already taken");
                }
                
                users.Add(user);
                await SaveUsersAsync(users);
                
                _logService.LogInfo($"User saved: {user.Username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error saving user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an existing user
        /// </summary>
        public async Task UpdateUserAsync(User user)
        {
            try
            {
                if (user == null)
                    throw new ArgumentNullException(nameof(user));
                
                var users = await GetAllUsersAsync();
                
                // Find the user to update
                var index = users.FindIndex(u => u.Id == user.Id);
                if (index == -1)
                {
                    throw new InvalidOperationException($"User with ID {user.Id} not found");
                }
                
                // Check for username conflicts with other users
                var usernameConflict = users.Any(u => u.Id != user.Id && 
                                                   u.Username.Equals(user.Username, StringComparison.OrdinalIgnoreCase));
                if (usernameConflict)
                {
                    throw new InvalidOperationException($"Username '{user.Username}' is already taken by another user");
                }
                
                users[index] = user;
                await SaveUsersAsync(users);
                
                _logService.LogInfo($"User updated: {user.Username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes a user by ID
        /// </summary>
        public async Task DeleteUserAsync(Guid id)
        {
            try
            {
                var users = await GetAllUsersAsync();
                
                // Find the user to delete
                var user = users.FirstOrDefault(u => u.Id == id);
                if (user == null)
                {
                    throw new InvalidOperationException($"User with ID {id} not found");
                }
                
                users.Remove(user);
                await SaveUsersAsync(users);
                
                _logService.LogInfo($"User deleted: {user.Username}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the list of users to file
        /// </summary>
        private async Task SaveUsersAsync(List<User> users)
        {
            var json = JsonSerializer.Serialize(users, _jsonOptions);
            await File.WriteAllTextAsync(_usersFilePath, json);
        }

        #endregion

        #region Threat Operations

        /// <summary>
        /// Gets all threats
        /// </summary>
        public async Task<List<Threat>> GetAllThreatsAsync()
        {
            try
            {
                var json = await File.ReadAllTextAsync(_threatsFilePath);
                var threats = JsonSerializer.Deserialize<List<Threat>>(json, _jsonOptions) ?? new List<Threat>();
                return threats;
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
                var threats = await GetAllThreatsAsync();
                return threats.FirstOrDefault(t => t.Id == id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting threat by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves a new threat
        /// </summary>
        public async Task SaveThreatAsync(Threat threat)
        {
            try
            {
                if (threat == null)
                    throw new ArgumentNullException(nameof(threat));
                
                var threats = await GetAllThreatsAsync();
                
                // Check if threat with same ID already exists
                if (threats.Any(t => t.Id == threat.Id))
                {
                    throw new InvalidOperationException($"Threat with ID {threat.Id} already exists");
                }
                
                threats.Add(threat);
                await SaveThreatsAsync(threats);
                
                _logService.LogInfo($"Threat saved: {threat.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error saving threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an existing threat
        /// </summary>
        public async Task UpdateThreatAsync(Threat threat)
        {
            try
            {
                if (threat == null)
                    throw new ArgumentNullException(nameof(threat));
                
                var threats = await GetAllThreatsAsync();
                
                // Find the threat to update
                var index = threats.FindIndex(t => t.Id == threat.Id);
                if (index == -1)
                {
                    throw new InvalidOperationException($"Threat with ID {threat.Id} not found");
                }
                
                threats[index] = threat;
                await SaveThreatsAsync(threats);
                
                _logService.LogInfo($"Threat updated: {threat.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes a threat by ID
        /// </summary>
        public async Task DeleteThreatAsync(Guid id)
        {
            try
            {
                var threats = await GetAllThreatsAsync();
                
                // Find the threat to delete
                var threat = threats.FirstOrDefault(t => t.Id == id);
                if (threat == null)
                {
                    throw new InvalidOperationException($"Threat with ID {id} not found");
                }
                
                threats.Remove(threat);
                await SaveThreatsAsync(threats);
                
                _logService.LogInfo($"Threat deleted: {threat.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting threat: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the list of threats to file
        /// </summary>
        private async Task SaveThreatsAsync(List<Threat> threats)
        {
            var json = JsonSerializer.Serialize(threats, _jsonOptions);
            await File.WriteAllTextAsync(_threatsFilePath, json);
        }

        #endregion

        #region Incident Operations

        /// <summary>
        /// Gets all incidents
        /// </summary>
        public async Task<List<Incident>> GetAllIncidentsAsync()
        {
            try
            {
                var json = await File.ReadAllTextAsync(_incidentsFilePath);
                var incidents = JsonSerializer.Deserialize<List<Incident>>(json, _jsonOptions) ?? new List<Incident>();
                return incidents;
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
                var incidents = await GetAllIncidentsAsync();
                return incidents.FirstOrDefault(i => i.Id == id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting incident by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves a new incident
        /// </summary>
        public async Task SaveIncidentAsync(Incident incident)
        {
            try
            {
                if (incident == null)
                    throw new ArgumentNullException(nameof(incident));
                
                var incidents = await GetAllIncidentsAsync();
                
                // Check if incident with same ID already exists
                if (incidents.Any(i => i.Id == incident.Id))
                {
                    throw new InvalidOperationException($"Incident with ID {incident.Id} already exists");
                }
                
                incidents.Add(incident);
                await SaveIncidentsAsync(incidents);
                
                _logService.LogInfo($"Incident saved: {incident.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error saving incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an existing incident
        /// </summary>
        public async Task UpdateIncidentAsync(Incident incident)
        {
            try
            {
                if (incident == null)
                    throw new ArgumentNullException(nameof(incident));
                
                var incidents = await GetAllIncidentsAsync();
                
                // Find the incident to update
                var index = incidents.FindIndex(i => i.Id == incident.Id);
                if (index == -1)
                {
                    throw new InvalidOperationException($"Incident with ID {incident.Id} not found");
                }
                
                incidents[index] = incident;
                await SaveIncidentsAsync(incidents);
                
                _logService.LogInfo($"Incident updated: {incident.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes an incident by ID
        /// </summary>
        public async Task DeleteIncidentAsync(Guid id)
        {
            try
            {
                var incidents = await GetAllIncidentsAsync();
                
                // Find the incident to delete
                var incident = incidents.FirstOrDefault(i => i.Id == id);
                if (incident == null)
                {
                    throw new InvalidOperationException($"Incident with ID {id} not found");
                }
                
                incidents.Remove(incident);
                await SaveIncidentsAsync(incidents);
                
                _logService.LogInfo($"Incident deleted: {incident.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting incident: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the list of incidents to file
        /// </summary>
        private async Task SaveIncidentsAsync(List<Incident> incidents)
        {
            var json = JsonSerializer.Serialize(incidents, _jsonOptions);
            await File.WriteAllTextAsync(_incidentsFilePath, json);
        }

        #endregion

        #region Vulnerability Operations

        /// <summary>
        /// Gets all vulnerabilities
        /// </summary>
        public async Task<List<Vulnerability>> GetAllVulnerabilitiesAsync()
        {
            try
            {
                var json = await File.ReadAllTextAsync(_vulnerabilitiesFilePath);
                var vulnerabilities = JsonSerializer.Deserialize<List<Vulnerability>>(json, _jsonOptions) ?? new List<Vulnerability>();
                return vulnerabilities;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all vulnerabilities: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Gets a vulnerability by ID
        /// </summary>
        public async Task<Vulnerability?> GetVulnerabilityByIdAsync(Guid id)
        {
            try
            {
                var vulnerabilities = await GetAllVulnerabilitiesAsync();
                return vulnerabilities.FirstOrDefault(v => v.Id == id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting vulnerability by ID: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves a new vulnerability
        /// </summary>
        public async Task SaveVulnerabilityAsync(Vulnerability vulnerability)
        {
            try
            {
                if (vulnerability == null)
                    throw new ArgumentNullException(nameof(vulnerability));
                
                var vulnerabilities = await GetAllVulnerabilitiesAsync();
                
                // Check if vulnerability with same ID already exists
                if (vulnerabilities.Any(v => v.Id == vulnerability.Id))
                {
                    throw new InvalidOperationException($"Vulnerability with ID {vulnerability.Id} already exists");
                }
                
                vulnerabilities.Add(vulnerability);
                await SaveVulnerabilitiesAsync(vulnerabilities);
                
                _logService.LogInfo($"Vulnerability saved: {vulnerability.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error saving vulnerability: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an existing vulnerability
        /// </summary>
        public async Task UpdateVulnerabilityAsync(Vulnerability vulnerability)
        {
            try
            {
                if (vulnerability == null)
                    throw new ArgumentNullException(nameof(vulnerability));
                
                var vulnerabilities = await GetAllVulnerabilitiesAsync();
                
                // Find the vulnerability to update
                var index = vulnerabilities.FindIndex(v => v.Id == vulnerability.Id);
                if (index == -1)
                {
                    throw new InvalidOperationException($"Vulnerability with ID {vulnerability.Id} not found");
                }
                
                vulnerabilities[index] = vulnerability;
                await SaveVulnerabilitiesAsync(vulnerabilities);
                
                _logService.LogInfo($"Vulnerability updated: {vulnerability.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating vulnerability: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes a vulnerability by ID
        /// </summary>
        public async Task DeleteVulnerabilityAsync(Guid id)
        {
            try
            {
                var vulnerabilities = await GetAllVulnerabilitiesAsync();
                
                // Find the vulnerability to delete
                var vulnerability = vulnerabilities.FirstOrDefault(v => v.Id == id);
                if (vulnerability == null)
                {
                    throw new InvalidOperationException($"Vulnerability with ID {id} not found");
                }
                
                vulnerabilities.Remove(vulnerability);
                await SaveVulnerabilitiesAsync(vulnerabilities);
                
                _logService.LogInfo($"Vulnerability deleted: {vulnerability.Name}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting vulnerability: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the list of vulnerabilities to file
        /// </summary>
        private async Task SaveVulnerabilitiesAsync(List<Vulnerability> vulnerabilities)
        {
            var json = JsonSerializer.Serialize(vulnerabilities, _jsonOptions);
            await File.WriteAllTextAsync(_vulnerabilitiesFilePath, json);
        }

        #endregion

        #region Alert Operations

        /// <summary>
        /// Gets all alerts
        /// </summary>
        public async Task<List<Alert>> GetAllAlertsAsync()
        {
            try
            {
                var json = await File.ReadAllTextAsync(_alertsFilePath);
                var alerts = JsonSerializer.Deserialize<List<Alert>>(json, _jsonOptions) ?? new List<Alert>();
                return alerts;
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting all alerts: {ex.Message}");
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
                var alerts = await GetAllAlertsAsync();
                return alerts.FirstOrDefault(a => a.Id == id);
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting alert by ID: {ex.Message}");
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
                var alerts = await GetAllAlertsAsync();
                return alerts.Where(a => !a.IsRead).ToList();
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
                var alerts = await GetAllAlertsAsync();
                return alerts.Where(a => !a.IsAcknowledged).ToList();
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error getting unacknowledged alerts: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves a new alert
        /// </summary>
        public async Task SaveAlertAsync(Alert alert)
        {
            try
            {
                if (alert == null)
                    throw new ArgumentNullException(nameof(alert));
                
                var alerts = await GetAllAlertsAsync();
                
                // Check if alert with same ID already exists
                if (alerts.Any(a => a.Id == alert.Id))
                {
                    throw new InvalidOperationException($"Alert with ID {alert.Id} already exists");
                }
                
                alerts.Add(alert);
                await SaveAlertsAsync(alerts);
                
                _logService.LogInfo($"Alert saved: {alert.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error saving alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Updates an existing alert
        /// </summary>
        public async Task UpdateAlertAsync(Alert alert)
        {
            try
            {
                if (alert == null)
                    throw new ArgumentNullException(nameof(alert));
                
                var alerts = await GetAllAlertsAsync();
                
                // Find the alert to update
                var index = alerts.FindIndex(a => a.Id == alert.Id);
                if (index == -1)
                {
                    throw new InvalidOperationException($"Alert with ID {alert.Id} not found");
                }
                
                alerts[index] = alert;
                await SaveAlertsAsync(alerts);
                
                _logService.LogInfo($"Alert updated: {alert.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error updating alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Deletes an alert by ID
        /// </summary>
        public async Task DeleteAlertAsync(Guid id)
        {
            try
            {
                var alerts = await GetAllAlertsAsync();
                
                // Find the alert to delete
                var alert = alerts.FirstOrDefault(a => a.Id == id);
                if (alert == null)
                {
                    throw new InvalidOperationException($"Alert with ID {id} not found");
                }
                
                alerts.Remove(alert);
                await SaveAlertsAsync(alerts);
                
                _logService.LogInfo($"Alert deleted: {alert.Title}");
            }
            catch (Exception ex)
            {
                _logService.LogError($"Error deleting alert: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the list of alerts to file
        /// </summary>
        private async Task SaveAlertsAsync(List<Alert> alerts)
        {
            var json = JsonSerializer.Serialize(alerts, _jsonOptions);
            await File.WriteAllTextAsync(_alertsFilePath, json);
        }

        #endregion
    }
}
