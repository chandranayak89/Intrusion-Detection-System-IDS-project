#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SOAR Integration Module
Provides integration with Security Orchestration, Automation and Response (SOAR) platforms
including TheHive and Splunk SOAR.
"""

import json
import time
import logging
import datetime
from typing import Dict, List, Any, Optional, Union, Callable
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger("ids.integrations.siem.soar")

class SoarConnector(ABC):
    """Base class for SOAR platform connectors"""
    
    @abstractmethod
    def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Create an alert in the SOAR platform
        
        Args:
            alert_data: Alert data
            
        Returns:
            ID of the created alert, or empty string on failure
        """
        pass
    
    @abstractmethod
    def create_case(self, case_data: Dict[str, Any]) -> str:
        """
        Create a case in the SOAR platform
        
        Args:
            case_data: Case data
            
        Returns:
            ID of the created case, or empty string on failure
        """
        pass
    
    @abstractmethod
    def add_observable(self, case_id: str, observable_data: Dict[str, Any]) -> bool:
        """
        Add an observable to a case
        
        Args:
            case_id: ID of the case
            observable_data: Observable data
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def add_task(self, case_id: str, task_data: Dict[str, Any]) -> bool:
        """
        Add a task to a case
        
        Args:
            case_id: ID of the case
            task_data: Task data
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def get_case_status(self, case_id: str) -> Dict[str, Any]:
        """
        Get the status of a case
        
        Args:
            case_id: ID of the case
            
        Returns:
            Case status data
        """
        pass

class TheHiveConnector(SoarConnector):
    """Connector for TheHive SOAR platform"""
    
    def __init__(self,
                 api_url: str,
                 api_key: str,
                 verify_ssl: bool = True,
                 proxies: Optional[Dict[str, str]] = None,
                 org_name: str = "default",
                 default_tlp: int = 2):  # TLP:AMBER
        """
        Initialize TheHive connector
        
        Args:
            api_url: URL of TheHive API
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            proxies: Optional proxy configuration
            org_name: Organization name
            default_tlp: Default TLP level (0-3)
        """
        self.api_url = api_url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.proxies = proxies
        self.org_name = org_name
        self.default_tlp = default_tlp
        self.client = None
        
        # Initialize the client
        try:
            from thehive4py.api import TheHiveApi
            
            self.client = TheHiveApi(
                self.api_url, 
                self.api_key, 
                cert=self.verify_ssl, 
                proxies=self.proxies,
                org_name=self.org_name
            )
            logger.info(f"Initialized TheHive connector for {self.api_url}")
            
        except ImportError:
            logger.error("thehive4py package not found. Install with: pip install thehive4py")
            self.client = None
    
    def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Create an alert in TheHive
        
        Args:
            alert_data: Alert data
            
        Returns:
            ID of the created alert, or empty string on failure
        """
        if not self.client:
            logger.error("TheHive client not initialized")
            return ""
            
        try:
            from thehive4py.models import Alert, AlertArtifact, CustomField
            
            # Map severity (0-3 in TheHive)
            severity_map = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 3
            }
            severity = severity_map.get(alert_data.get("severity", "").lower(), 2)
            
            # Create artifacts from observables
            artifacts = []
            for observable in alert_data.get("observables", []):
                # Map observable type
                data_type = observable.get("type", "")
                if data_type == "ip":
                    data_type = "ip"
                elif data_type in ["domain", "hostname"]:
                    data_type = "domain"
                elif data_type == "url":
                    data_type = "url"
                elif data_type in ["md5", "sha1", "sha256"]:
                    data_type = "hash"
                elif data_type == "email":
                    data_type = "mail"
                elif data_type == "file":
                    data_type = "file"
                else:
                    data_type = "other"
                
                artifact = AlertArtifact(
                    dataType=data_type,
                    data=observable.get("value", ""),
                    message=observable.get("description", ""),
                    tags=observable.get("tags", [])
                )
                artifacts.append(artifact)
            
            # Create custom fields
            custom_fields = {}
            for field_name, field_value in alert_data.get("custom_fields", {}).items():
                # For simplicity, we're treating all custom fields as strings
                # In a real implementation, you'd need to handle different field types
                custom_fields[field_name] = CustomField(field_name, "string", field_value)
            
            # Create the alert
            alert = Alert(
                title=alert_data.get("title", "IDS Alert"),
                description=alert_data.get("description", ""),
                type=alert_data.get("type", "ids"),
                source=alert_data.get("source", "IDS"),
                sourceRef=alert_data.get("id", str(int(time.time()))),
                severity=severity,
                tlp=alert_data.get("tlp", self.default_tlp),
                tags=alert_data.get("tags", []),
                artifacts=artifacts,
                customFields=custom_fields
            )
            
            # Submit the alert
            response = self.client.create_alert(alert)
            
            if response.status_code == 201:
                alert_id = response.json().get("id", "")
                logger.info(f"Successfully created TheHive alert with ID: {alert_id}")
                return alert_id
            else:
                logger.error(f"Failed to create TheHive alert: {response.status_code} - {response.text}")
                return ""
                
        except Exception as e:
            logger.error(f"Error creating TheHive alert: {e}")
            return ""
    
    def create_case(self, case_data: Dict[str, Any]) -> str:
        """
        Create a case in TheHive
        
        Args:
            case_data: Case data
            
        Returns:
            ID of the created case, or empty string on failure
        """
        if not self.client:
            logger.error("TheHive client not initialized")
            return ""
            
        try:
            from thehive4py.models import Case, CaseTask, CaseObservable, CustomField
            
            # Map severity (0-3 in TheHive)
            severity_map = {
                "low": 1,
                "medium": 2,
                "high": 3,
                "critical": 3
            }
            severity = severity_map.get(case_data.get("severity", "").lower(), 2)
            
            # Create custom fields
            custom_fields = {}
            for field_name, field_value in case_data.get("custom_fields", {}).items():
                # For simplicity, we're treating all custom fields as strings
                custom_fields[field_name] = CustomField(field_name, "string", field_value)
            
            # Create the case
            case = Case(
                title=case_data.get("title", "IDS Case"),
                description=case_data.get("description", ""),
                severity=severity,
                tlp=case_data.get("tlp", self.default_tlp),
                tags=case_data.get("tags", []),
                customFields=custom_fields
            )
            
            # Submit the case
            response = self.client.create_case(case)
            
            if response.status_code == 201:
                case_id = response.json().get("id", "")
                logger.info(f"Successfully created TheHive case with ID: {case_id}")
                
                # Add tasks if provided
                for task_data in case_data.get("tasks", []):
                    self.add_task(case_id, task_data)
                
                # Add observables if provided
                for observable_data in case_data.get("observables", []):
                    self.add_observable(case_id, observable_data)
                
                return case_id
            else:
                logger.error(f"Failed to create TheHive case: {response.status_code} - {response.text}")
                return ""
                
        except Exception as e:
            logger.error(f"Error creating TheHive case: {e}")
            return ""
    
    def add_observable(self, case_id: str, observable_data: Dict[str, Any]) -> bool:
        """
        Add an observable to a case
        
        Args:
            case_id: ID of the case
            observable_data: Observable data
            
        Returns:
            True if successful, False otherwise
        """
        if not self.client:
            logger.error("TheHive client not initialized")
            return False
            
        try:
            from thehive4py.models import CaseObservable
            
            # Map observable type
            data_type = observable_data.get("type", "")
            if data_type == "ip":
                data_type = "ip"
            elif data_type in ["domain", "hostname"]:
                data_type = "domain"
            elif data_type == "url":
                data_type = "url"
            elif data_type in ["md5", "sha1", "sha256"]:
                data_type = "hash"
            elif data_type == "email":
                data_type = "mail"
            elif data_type == "file":
                data_type = "file"
            else:
                data_type = "other"
            
            # Create the observable
            observable = CaseObservable(
                dataType=data_type,
                data=observable_data.get("value", ""),
                message=observable_data.get("description", ""),
                tlp=observable_data.get("tlp", self.default_tlp),
                ioc=observable_data.get("ioc", False),
                tags=observable_data.get("tags", [])
            )
            
            # Add the observable to the case
            response = self.client.create_case_observable(case_id, observable)
            
            if response.status_code == 201:
                logger.info(f"Successfully added observable to TheHive case {case_id}")
                return True
            else:
                logger.error(f"Failed to add observable to TheHive case: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding observable to TheHive case: {e}")
            return False
    
    def add_task(self, case_id: str, task_data: Dict[str, Any]) -> bool:
        """
        Add a task to a case
        
        Args:
            case_id: ID of the case
            task_data: Task data
            
        Returns:
            True if successful, False otherwise
        """
        if not self.client:
            logger.error("TheHive client not initialized")
            return False
            
        try:
            from thehive4py.models import CaseTask
            
            # Create the task
            task = CaseTask(
                title=task_data.get("title", "Investigation Task"),
                status=task_data.get("status", "Waiting"),
                flag=task_data.get("flag", False),
                description=task_data.get("description", ""),
                owner=task_data.get("owner", "")
            )
            
            # Add the task to the case
            response = self.client.create_case_task(case_id, task)
            
            if response.status_code == 201:
                logger.info(f"Successfully added task to TheHive case {case_id}")
                return True
            else:
                logger.error(f"Failed to add task to TheHive case: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding task to TheHive case: {e}")
            return False
    
    def get_case_status(self, case_id: str) -> Dict[str, Any]:
        """
        Get the status of a case
        
        Args:
            case_id: ID of the case
            
        Returns:
            Case status data
        """
        if not self.client:
            logger.error("TheHive client not initialized")
            return {}
            
        try:
            # Get the case
            response = self.client.get_case(case_id)
            
            if response.status_code == 200:
                case_data = response.json()
                
                # Extract relevant status information
                status = {
                    "id": case_data.get("id", ""),
                    "title": case_data.get("title", ""),
                    "status": case_data.get("status", ""),
                    "severity": case_data.get("severity", 0),
                    "tlp": case_data.get("tlp", 0),
                    "tags": case_data.get("tags", []),
                    "createdAt": case_data.get("createdAt", 0),
                    "updatedAt": case_data.get("updatedAt", 0),
                    "owner": case_data.get("owner", ""),
                    "flag": case_data.get("flag", False),
                    "open": case_data.get("status", "") != "Resolved"
                }
                return status
            else:
                logger.error(f"Failed to get TheHive case status: {response.status_code} - {response.text}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting TheHive case status: {e}")
            return {}

class SplunkSoarConnector(SoarConnector):
    """Connector for Splunk SOAR platform"""
    
    def __init__(self,
                 api_url: str,
                 api_token: str,
                 verify_ssl: bool = True,
                 container_label: str = "IDS Alert",
                 default_severity: str = "medium",
                 default_sensitivity: str = "amber"):
        """
        Initialize Splunk SOAR connector
        
        Args:
            api_url: URL of Splunk SOAR API
            api_token: API token for authentication
            verify_ssl: Whether to verify SSL certificates
            container_label: Default container label
            default_severity: Default severity level
            default_sensitivity: Default sensitivity level
        """
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.container_label = container_label
        self.default_severity = default_severity
        self.default_sensitivity = default_sensitivity
        
        # Initialize the HTTP client
        try:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'Authorization': f'Splunk {self.api_token}',
                'Content-Type': 'application/json'
            })
            logger.info(f"Initialized Splunk SOAR connector for {self.api_url}")
            
        except ImportError:
            logger.error("requests package not found. Install with: pip install requests")
            self.session = None
    
    def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """
        Create an alert in Splunk SOAR (as a container)
        
        Args:
            alert_data: Alert data
            
        Returns:
            ID of the created container, or empty string on failure
        """
        if not self.session:
            logger.error("Splunk SOAR session not initialized")
            return ""
            
        try:
            # Map severity
            severity_map = {
                "low": "low",
                "medium": "medium",
                "high": "high",
                "critical": "high"
            }
            severity = severity_map.get(alert_data.get("severity", "").lower(), self.default_severity)
            
            # Map sensitivity (TLP)
            sensitivity_map = {
                0: "white",  # TLP:WHITE
                1: "green",  # TLP:GREEN
                2: "amber",  # TLP:AMBER
                3: "red"     # TLP:RED
            }
            tlp = alert_data.get("tlp", 2)  # Default to TLP:AMBER
            sensitivity = sensitivity_map.get(tlp, self.default_sensitivity)
            
            # Create container payload
            container = {
                "name": alert_data.get("title", "IDS Alert"),
                "description": alert_data.get("description", ""),
                "label": alert_data.get("type", self.container_label),
                "source_data_identifier": alert_data.get("id", str(int(time.time()))),
                "severity": severity,
                "sensitivity": sensitivity,
                "tags": alert_data.get("tags", []),
                "data": {
                    "source": alert_data.get("source", "IDS"),
                    "custom_fields": alert_data.get("custom_fields", {})
                }
            }
            
            # Create the container
            response = self.session.post(
                f"{self.api_url}/rest/container",
                json=container,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("success", False):
                    container_id = str(result.get("id", ""))
                    logger.info(f"Successfully created Splunk SOAR container with ID: {container_id}")
                    
                    # Add artifacts for observables
                    for observable in alert_data.get("observables", []):
                        artifact = {
                            "name": observable.get("description", "Observable"),
                            "label": observable.get("type", "other"),
                            "severity": severity,
                            "type": "network",  # Default type
                            "source_data_identifier": f"{container_id}-{observable.get('value', '')}",
                            "cef": {
                                "value": observable.get("value", ""),
                                "type": observable.get("type", "other"),
                                "description": observable.get("description", "")
                            },
                            "tags": observable.get("tags", []),
                            "container_id": container_id
                        }
                        
                        # Adjust artifact type based on observable type
                        observable_type = observable.get("type", "").lower()
                        if observable_type in ["ip", "domain", "url", "hostname"]:
                            artifact["type"] = "network"
                        elif observable_type in ["md5", "sha1", "sha256", "file"]:
                            artifact["type"] = "file"
                        elif observable_type == "email":
                            artifact["type"] = "email"
                        else:
                            artifact["type"] = "other"
                        
                        # Add the artifact
                        artifact_response = self.session.post(
                            f"{self.api_url}/rest/artifact",
                            json=artifact,
                            verify=self.verify_ssl
                        )
                        
                        if artifact_response.status_code != 200 or not artifact_response.json().get("success", False):
                            logger.warning(f"Failed to add artifact to Splunk SOAR container: {artifact_response.text}")
                    
                    return container_id
                else:
                    logger.error(f"Failed to create Splunk SOAR container: {result.get('message', 'Unknown error')}")
                    return ""
            else:
                logger.error(f"Failed to create Splunk SOAR container: {response.status_code} - {response.text}")
                return ""
                
        except Exception as e:
            logger.error(f"Error creating Splunk SOAR container: {e}")
            return ""
    
    def create_case(self, case_data: Dict[str, Any]) -> str:
        """
        Create a case in Splunk SOAR (as a container)
        
        Args:
            case_data: Case data
            
        Returns:
            ID of the created case, or empty string on failure
        """
        # In Splunk SOAR, cases are just containers with different settings
        # We'll create a container and then add a note indicating it's a case
        container_id = self.create_alert(case_data)
        
        if container_id:
            # Add a note indicating this is a case
            try:
                note = {
                    "title": "Case Information",
                    "content": f"This container represents a case created at {datetime.datetime.now().isoformat()}.\n\nCase Details:\n{case_data.get('description', '')}",
                    "note_type": "general",
                    "container_id": container_id
                }
                
                response = self.session.post(
                    f"{self.api_url}/rest/note",
                    json=note,
                    verify=self.verify_ssl
                )
                
                if response.status_code != 200 or not response.json().get("success", False):
                    logger.warning(f"Failed to add case note to Splunk SOAR container: {response.text}")
                
                # Add tasks if provided
                for task_data in case_data.get("tasks", []):
                    self.add_task(container_id, task_data)
                
            except Exception as e:
                logger.error(f"Error adding case information to Splunk SOAR container: {e}")
        
        return container_id
    
    def add_observable(self, case_id: str, observable_data: Dict[str, Any]) -> bool:
        """
        Add an observable to a case (as an artifact)
        
        Args:
            case_id: ID of the case (container)
            observable_data: Observable data
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            logger.error("Splunk SOAR session not initialized")
            return False
            
        try:
            # Create artifact for the observable
            artifact = {
                "name": observable_data.get("description", "Observable"),
                "label": observable_data.get("type", "other"),
                "severity": self.default_severity,
                "type": "network",  # Default type
                "source_data_identifier": f"{case_id}-{observable_data.get('value', '')}",
                "cef": {
                    "value": observable_data.get("value", ""),
                    "type": observable_data.get("type", "other"),
                    "description": observable_data.get("description", "")
                },
                "tags": observable_data.get("tags", []),
                "container_id": case_id
            }
            
            # Adjust artifact type based on observable type
            observable_type = observable_data.get("type", "").lower()
            if observable_type in ["ip", "domain", "url", "hostname"]:
                artifact["type"] = "network"
            elif observable_type in ["md5", "sha1", "sha256", "file"]:
                artifact["type"] = "file"
            elif observable_type == "email":
                artifact["type"] = "email"
            else:
                artifact["type"] = "other"
            
            # Add the artifact
            response = self.session.post(
                f"{self.api_url}/rest/artifact",
                json=artifact,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200 and response.json().get("success", False):
                logger.info(f"Successfully added artifact to Splunk SOAR container {case_id}")
                return True
            else:
                logger.error(f"Failed to add artifact to Splunk SOAR container: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding artifact to Splunk SOAR container: {e}")
            return False
    
    def add_task(self, case_id: str, task_data: Dict[str, Any]) -> bool:
        """
        Add a task to a case (as a custom task)
        
        Args:
            case_id: ID of the case (container)
            task_data: Task data
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            logger.error("Splunk SOAR session not initialized")
            return False
            
        try:
            # Create a note for the task (Splunk SOAR has no direct task API)
            task_status = task_data.get("status", "Pending")
            task_owner = task_data.get("owner", "Unassigned")
            
            note = {
                "title": f"Task: {task_data.get('title', 'Investigation Task')}",
                "content": f"**Status:** {task_status}\n**Owner:** {task_owner}\n\n{task_data.get('description', '')}",
                "note_type": "task",
                "container_id": case_id
            }
            
            response = self.session.post(
                f"{self.api_url}/rest/note",
                json=note,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200 and response.json().get("success", False):
                logger.info(f"Successfully added task to Splunk SOAR container {case_id}")
                return True
            else:
                logger.error(f"Failed to add task to Splunk SOAR container: {response.status_code} - {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error adding task to Splunk SOAR container: {e}")
            return False
    
    def get_case_status(self, case_id: str) -> Dict[str, Any]:
        """
        Get the status of a case
        
        Args:
            case_id: ID of the case (container)
            
        Returns:
            Case status data
        """
        if not self.session:
            logger.error("Splunk SOAR session not initialized")
            return {}
            
        try:
            # Get the container
            response = self.session.get(
                f"{self.api_url}/rest/container/{case_id}",
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                result = response.json()
                container = result.get("data", {})
                
                # Extract relevant status information
                status = {
                    "id": container.get("id", ""),
                    "name": container.get("name", ""),
                    "status": container.get("status", "new"),
                    "severity": container.get("severity", ""),
                    "sensitivity": container.get("sensitivity", ""),
                    "tags": container.get("tags", []),
                    "create_time": container.get("create_time", ""),
                    "close_time": container.get("close_time", ""),
                    "owner": container.get("owner_name", ""),
                    "open": container.get("status", "new") != "closed"
                }
                return status
            else:
                logger.error(f"Failed to get Splunk SOAR container status: {response.status_code} - {response.text}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting Splunk SOAR container status: {e}")
            return {}

class SoarIntegration:
    """Manager for SOAR platform integrations"""
    
    def __init__(self):
        """Initialize the SOAR integration manager"""
        self.connectors = {}
    
    def add_connector(self, name: str, connector: SoarConnector) -> None:
        """
        Add a SOAR connector
        
        Args:
            name: Name of the connector
            connector: SOAR connector instance
        """
        self.connectors[name] = connector
    
    def remove_connector(self, name: str) -> None:
        """
        Remove a SOAR connector
        
        Args:
            name: Name of the connector
        """
        if name in self.connectors:
            del self.connectors[name]
    
    def get_connector(self, name: str) -> Optional[SoarConnector]:
        """
        Get a SOAR connector by name
        
        Args:
            name: Name of the connector
            
        Returns:
            SOAR connector instance or None if not found
        """
        return self.connectors.get(name)
    
    def create_alert(self, 
                     alert_data: Dict[str, Any], 
                     connectors: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Create an alert in specified SOAR platforms
        
        Args:
            alert_data: Alert data
            connectors: List of connector names to use (if None, use all)
            
        Returns:
            Dictionary of connector name to alert ID
        """
        results = {}
        
        # Determine which connectors to use
        if connectors:
            connectors_to_use = {name: self.connectors[name] for name in connectors if name in self.connectors}
        else:
            connectors_to_use = self.connectors
        
        # Create alerts in each platform
        for name, connector in connectors_to_use.items():
            try:
                alert_id = connector.create_alert(alert_data)
                results[name] = alert_id
            except Exception as e:
                logger.error(f"Error creating alert with connector {name}: {e}")
                results[name] = ""
        
        return results
    
    def create_case(self, 
                    case_data: Dict[str, Any], 
                    connectors: Optional[List[str]] = None) -> Dict[str, str]:
        """
        Create a case in specified SOAR platforms
        
        Args:
            case_data: Case data
            connectors: List of connector names to use (if None, use all)
            
        Returns:
            Dictionary of connector name to case ID
        """
        results = {}
        
        # Determine which connectors to use
        if connectors:
            connectors_to_use = {name: self.connectors[name] for name in connectors if name in self.connectors}
        else:
            connectors_to_use = self.connectors
        
        # Create cases in each platform
        for name, connector in connectors_to_use.items():
            try:
                case_id = connector.create_case(case_data)
                results[name] = case_id
            except Exception as e:
                logger.error(f"Error creating case with connector {name}: {e}")
                results[name] = ""
        
        return results
    
    def add_observable(self, 
                       case_ids: Dict[str, str], 
                       observable_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Add an observable to cases in specified SOAR platforms
        
        Args:
            case_ids: Dictionary of connector name to case ID
            observable_data: Observable data
            
        Returns:
            Dictionary of connector name to success status
        """
        results = {}
        
        # Add observable to each case
        for name, case_id in case_ids.items():
            if not case_id:
                results[name] = False
                continue
                
            connector = self.connectors.get(name)
            if not connector:
                results[name] = False
                continue
                
            try:
                success = connector.add_observable(case_id, observable_data)
                results[name] = success
            except Exception as e:
                logger.error(f"Error adding observable with connector {name}: {e}")
                results[name] = False
        
        return results
    
    def add_task(self, 
                case_ids: Dict[str, str], 
                task_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Add a task to cases in specified SOAR platforms
        
        Args:
            case_ids: Dictionary of connector name to case ID
            task_data: Task data
            
        Returns:
            Dictionary of connector name to success status
        """
        results = {}
        
        # Add task to each case
        for name, case_id in case_ids.items():
            if not case_id:
                results[name] = False
                continue
                
            connector = self.connectors.get(name)
            if not connector:
                results[name] = False
                continue
                
            try:
                success = connector.add_task(case_id, task_data)
                results[name] = success
            except Exception as e:
                logger.error(f"Error adding task with connector {name}: {e}")
                results[name] = False
        
        return results
    
    def get_case_status(self, 
                       case_ids: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """
        Get the status of cases in specified SOAR platforms
        
        Args:
            case_ids: Dictionary of connector name to case ID
            
        Returns:
            Dictionary of connector name to case status
        """
        results = {}
        
        # Get status of each case
        for name, case_id in case_ids.items():
            if not case_id:
                results[name] = {}
                continue
                
            connector = self.connectors.get(name)
            if not connector:
                results[name] = {}
                continue
                
            try:
                status = connector.get_case_status(case_id)
                results[name] = status
            except Exception as e:
                logger.error(f"Error getting case status with connector {name}: {e}")
                results[name] = {}
        
        return results 