# SIEM & Incident Response Integration

This module provides integration capabilities between the Intrusion Detection System (IDS) and Security Information and Event Management (SIEM) systems, as well as incident response workflows.

## Features

### 1. SOAR Integration

Integration with Security Orchestration, Automation, and Response (SOAR) platforms:

- **TheHive**: Create alerts and cases, add observables, tasks, and comments
- **Splunk SOAR**: Create events, containers, artifacts, and automated playbooks

### 2. Log Enrichment

Enrich IDS alerts with contextual metadata:

- **GeoIP**: Add geographical information for IP addresses
- **DNS**: Add DNS resolution (reverse and forward) for IPs and hostnames
- **Threat Intelligence**: Enrich indicators with threat intelligence data

### 3. Notifications

Send notifications about IDS alerts through various channels:

- **Slack**: Send alerts to Slack channels
- **Email**: Send email notifications
- **PagerDuty**: Create incidents in PagerDuty

## Architecture

The module is designed with a modular architecture:

- **Base Classes**: Abstract interfaces for each functional area
- **Implementations**: Concrete implementations for specific platforms
- **Managers**: Composite classes that manage multiple implementations

## Setup and Configuration

1. Install required dependencies:
   ```bash
   pip install requests thehive4py python-geoip-geolite2 dnspython pydantic
   ```

2. Configure the module by editing the configuration file:
   ```
   src/integrations/siem/config/siem_config.yaml
   ```

3. Enable the features you want to use by setting `enabled: true` in the appropriate sections.

4. Add the required API keys and connection information for each service.

## Usage Examples

### Basic Usage

```python
from src.integrations.siem import (
    LogEnricher, 
    NotificationManager, 
    SoarIntegration
)

# Create and enrich an alert
alert = {
    "id": "IDS-ALERT-123",
    "timestamp": "2023-01-01T12:00:00Z",
    "title": "Suspicious Network Traffic Detected",
    "severity": "medium",
    "source_ip": "192.168.1.100"
}

# Enrich the alert with contextual data
enricher = LogEnricher()
enriched_alert = enricher.enrich(alert)

# Send notifications
notification_manager = NotificationManager()
notification_manager.send_notification(
    title=enriched_alert["title"],
    message=enriched_alert["description"],
    severity=enriched_alert["severity"],
    data=enriched_alert
)

# Create SOAR case
soar = SoarIntegration()
case_id = soar.create_case(enriched_alert, title="Investigation: " + enriched_alert["title"])
```

### For More Examples

See the examples directory for more detailed usage examples:

- `src/integrations/siem/examples/siem_integration_example.py`: Demonstrates all components working together
- `src/integrations/siem/examples/soar_example.py`: Demonstrates SOAR integration

## Configuration Reference

The configuration file (`siem_config.yaml`) contains settings for all components:

- **Log Enrichment**: GeoIP, DNS, and threat intelligence settings
- **Notifications**: Slack, Email, and PagerDuty settings
- **SOAR Integration**: TheHive and Splunk SOAR settings
- **Alert Templates**: Templates for formatting alerts for different platforms

Refer to the comments in the configuration file for detailed explanations of each setting.

## Extending the Module

The module is designed to be easily extended with new integrations:

1. Create a new class implementing the appropriate base interface
2. Register your implementation with the appropriate manager
3. Add configuration options to the YAML file

For example, to add a new notification provider:

```python
from src.integrations.siem.notification import Notifier

class TeamsNotifier(Notifier):
    def __init__(self, webhook_url, ...):
        # Initialize the notifier
        
    def send_notification(self, title, message, ...):
        # Send notification to Microsoft Teams
        
# Register with the notification manager
notification_manager.add_notifier("teams", TeamsNotifier(...))
``` 