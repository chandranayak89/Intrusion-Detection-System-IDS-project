#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Notification Module
Provides capabilities to send notifications about IDS alerts to various
platforms including Slack, Email, and PagerDuty.
"""

import os
import json
import time
import logging
import smtplib
import threading
import concurrent.futures
from typing import Dict, List, Any, Optional, Union, Callable, Set
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from abc import ABC, abstractmethod
from datetime import datetime

# Configure logging
logger = logging.getLogger("ids.integrations.siem.notification")

class Notifier(ABC):
    """Base class for notification providers"""
    
    @abstractmethod
    def send_notification(self, 
                         title: str, 
                         message: str, 
                         data: Optional[Dict[str, Any]] = None, 
                         severity: str = "medium",
                         tags: Optional[List[str]] = None) -> bool:
        """
        Send a notification
        
        Args:
            title: Title of the notification
            message: Message body
            data: Additional data to include in the notification
            severity: Severity of the alert (low, medium, high, critical)
            tags: Tags to include in the notification
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    def send_batch(self, 
                  notifications: List[Dict[str, Any]]) -> List[bool]:
        """
        Send a batch of notifications
        
        Args:
            notifications: List of notification data dictionaries
            
        Returns:
            List of success status for each notification
        """
        results = []
        for notification in notifications:
            success = self.send_notification(
                title=notification.get("title", "IDS Alert"),
                message=notification.get("message", ""),
                data=notification.get("data"),
                severity=notification.get("severity", "medium"),
                tags=notification.get("tags")
            )
            results.append(success)
        return results

class SlackNotifier(Notifier):
    """Sends notifications to Slack via webhooks"""
    
    def __init__(self, 
                webhook_url: str,
                channel: Optional[str] = None,
                username: str = "IDS Alert System",
                icon_emoji: str = ":warning:",
                timeout: float = 5.0,
                batch_size: int = 10,
                max_retries: int = 3,
                include_full_data: bool = False):
        """
        Initialize Slack notifier
        
        Args:
            webhook_url: Slack webhook URL
            channel: Optional channel override
            username: Username to display for notifications
            icon_emoji: Emoji to use as icon
            timeout: Request timeout in seconds
            batch_size: Maximum number of notifications to send in one batch
            max_retries: Maximum number of retry attempts
            include_full_data: Whether to include full alert data in notification
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.icon_emoji = icon_emoji
        self.timeout = timeout
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.include_full_data = include_full_data
        
        # Initialize HTTP session
        self.session = None
        try:
            import requests
            self.session = requests.Session()
            logger.info("Initialized Slack notifier")
        except ImportError:
            logger.error("requests package not found. Install with: pip install requests")
    
    def send_notification(self, 
                         title: str, 
                         message: str, 
                         data: Optional[Dict[str, Any]] = None, 
                         severity: str = "medium",
                         tags: Optional[List[str]] = None) -> bool:
        """
        Send a notification to Slack
        
        Args:
            title: Title of the notification
            message: Message body
            data: Additional data to include in the notification
            severity: Severity of the alert (low, medium, high, critical)
            tags: Tags to include in the notification
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            logger.error("Slack session not initialized")
            return False
        
        try:
            # Determine color based on severity
            color_map = {
                "low": "#36a64f",      # Green
                "medium": "#f2c744",   # Yellow
                "high": "#ff9000",     # Orange
                "critical": "#ff0000"  # Red
            }
            color = color_map.get(severity.lower(), "#f2c744")
            
            # Format tags if provided
            tags_str = ""
            if tags:
                tags_str = "\n*Tags:* " + ", ".join([f"`{tag}`" for tag in tags])
            
            # Create attachment
            attachment = {
                "color": color,
                "title": title,
                "text": message + tags_str,
                "ts": int(time.time())
            }
            
            # Add fields from data if needed
            if data and self.include_full_data:
                fields = []
                for key, value in data.items():
                    # Skip large or complex objects
                    if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and len(value) < 5):
                        fields.append({
                            "title": key,
                            "value": str(value),
                            "short": len(str(value)) < 20
                        })
                
                if fields:
                    attachment["fields"] = fields
            
            # Prepare payload
            payload = {
                "username": self.username,
                "icon_emoji": self.icon_emoji,
                "attachments": [attachment]
            }
            
            # Add channel if specified
            if self.channel:
                payload["channel"] = self.channel
            
            # Send to Slack
            for attempt in range(self.max_retries):
                response = self.session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout
                )
                
                if response.status_code == 200 and response.text == "ok":
                    logger.info(f"Successfully sent Slack notification: {title}")
                    return True
                else:
                    logger.warning(f"Failed to send Slack notification (attempt {attempt+1}/{self.max_retries}): {response.status_code} - {response.text}")
                    time.sleep(1)  # Wait before retrying
            
            logger.error(f"Failed to send Slack notification after {self.max_retries} attempts: {title}")
            return False
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    def send_batch(self, notifications: List[Dict[str, Any]]) -> List[bool]:
        """
        Send a batch of notifications to Slack
        
        Args:
            notifications: List of notification data dictionaries
            
        Returns:
            List of success status for each notification
        """
        if not self.session:
            logger.error("Slack session not initialized")
            return [False] * len(notifications)
        
        # Process in smaller batches to avoid overloading Slack API
        results = []
        
        for i in range(0, len(notifications), self.batch_size):
            batch = notifications[i:i+self.batch_size]
            
            # Use ThreadPoolExecutor for parallel processing
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Create notification tasks
                tasks = []
                for notification in batch:
                    tasks.append(executor.submit(
                        self.send_notification,
                        title=notification.get("title", "IDS Alert"),
                        message=notification.get("message", ""),
                        data=notification.get("data"),
                        severity=notification.get("severity", "medium"),
                        tags=notification.get("tags")
                    ))
                
                # Collect results
                for task in concurrent.futures.as_completed(tasks):
                    results.append(task.result())
        
        return results

class EmailNotifier(Notifier):
    """Sends notifications via email"""
    
    def __init__(self,
                smtp_server: str,
                smtp_port: int = 587,
                use_tls: bool = True,
                username: Optional[str] = None,
                password: Optional[str] = None,
                from_address: str = "ids-alerts@example.com",
                to_addresses: List[str] = None,
                cc_addresses: List[str] = None,
                bcc_addresses: List[str] = None,
                max_retries: int = 3,
                template_path: Optional[str] = None):
        """
        Initialize Email notifier
        
        Args:
            smtp_server: SMTP server hostname
            smtp_port: SMTP server port
            use_tls: Whether to use TLS encryption
            username: Username for SMTP authentication
            password: Password for SMTP authentication
            from_address: Email address to send from
            to_addresses: List of recipient email addresses
            cc_addresses: List of CC recipient email addresses
            bcc_addresses: List of BCC recipient email addresses
            max_retries: Maximum number of retry attempts
            template_path: Path to HTML email template
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.from_address = from_address
        self.to_addresses = to_addresses or []
        self.cc_addresses = cc_addresses or []
        self.bcc_addresses = bcc_addresses or []
        self.max_retries = max_retries
        self.template_path = template_path
        
        # Load template if provided
        self.template = None
        if template_path and os.path.exists(template_path):
            try:
                with open(template_path, 'r') as f:
                    self.template = f.read()
                logger.info(f"Loaded email template from {template_path}")
            except Exception as e:
                logger.error(f"Error loading email template: {e}")
        
        logger.info("Initialized Email notifier")
    
    def send_notification(self, 
                         title: str, 
                         message: str, 
                         data: Optional[Dict[str, Any]] = None, 
                         severity: str = "medium",
                         tags: Optional[List[str]] = None) -> bool:
        """
        Send a notification via email
        
        Args:
            title: Title of the notification
            message: Message body
            data: Additional data to include in the notification
            severity: Severity of the alert (low, medium, high, critical)
            tags: Tags to include in the notification
            
        Returns:
            True if successful, False otherwise
        """
        if not self.to_addresses:
            logger.error("No recipient email addresses specified")
            return False
        
        try:
            # Create email message
            email = MIMEMultipart("alternative")
            email["Subject"] = f"[{severity.upper()}] {title}"
            email["From"] = self.from_address
            email["To"] = ", ".join(self.to_addresses)
            
            if self.cc_addresses:
                email["Cc"] = ", ".join(self.cc_addresses)
            
            # Format tags as a string
            tags_str = ""
            if tags:
                tags_str = "Tags: " + ", ".join(tags)
            
            # Create plain text version
            plain_text = f"{title}\n\n{message}\n\n{tags_str}\n\n"
            
            # Add data fields if available
            if data:
                plain_text += "Additional Information:\n"
                for key, value in data.items():
                    if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and len(value) < 5):
                        plain_text += f"{key}: {value}\n"
            
            # Attach plain text version
            email.attach(MIMEText(plain_text, "plain"))
            
            # Create HTML version
            if self.template:
                # Use the template if available
                html_content = self.template
                
                # Substitute variables in template
                html_content = html_content.replace("{{title}}", title)
                html_content = html_content.replace("{{message}}", message.replace("\n", "<br>"))
                html_content = html_content.replace("{{severity}}", severity.upper())
                html_content = html_content.replace("{{time}}", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
                # Add tags
                if tags:
                    tags_html = ", ".join([f'<span class="tag">{tag}</span>' for tag in tags])
                else:
                    tags_html = ""
                html_content = html_content.replace("{{tags}}", tags_html)
                
                # Add data fields
                data_html = ""
                if data:
                    data_html += "<table class='data-table'><tr><th>Field</th><th>Value</th></tr>"
                    for key, value in data.items():
                        if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and len(value) < 5):
                            data_html += f"<tr><td>{key}</td><td>{value}</td></tr>"
                    data_html += "</table>"
                html_content = html_content.replace("{{data}}", data_html)
                
            else:
                # Create a basic HTML version if no template
                severity_colors = {
                    "low": "#36a64f",      # Green
                    "medium": "#f2c744",   # Yellow
                    "high": "#ff9000",     # Orange
                    "critical": "#ff0000"  # Red
                }
                color = severity_colors.get(severity.lower(), "#f2c744")
                
                html_content = f"""
                <html>
                <head>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
                        .header {{ background-color: #f2f2f2; padding: 10px; border-bottom: 1px solid #ddd; }}
                        .severity {{ display: inline-block; padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; background-color: {color}; }}
                        .content {{ padding: 20px 0; }}
                        .tag {{ background-color: #eee; padding: 3px 8px; border-radius: 3px; margin-right: 5px; }}
                        .data-table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
                        .data-table th, .data-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                        .data-table th {{ background-color: #f2f2f2; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h2>{title}</h2>
                        <div class="severity">{severity.upper()}</div>
                        <div style="margin-top: 5px;">Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                    </div>
                    <div class="content">
                        <p>{message.replace("\n", "<br>")}</p>
                """
                
                # Add tags
                if tags:
                    html_content += "<div style='margin-top: 15px;'>Tags: "
                    for tag in tags:
                        html_content += f'<span class="tag">{tag}</span> '
                    html_content += "</div>"
                
                # Add data fields
                if data:
                    html_content += "<table class='data-table'><tr><th>Field</th><th>Value</th></tr>"
                    for key, value in data.items():
                        if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and len(value) < 5):
                            html_content += f"<tr><td>{key}</td><td>{value}</td></tr>"
                    html_content += "</table>"
                
                html_content += """
                    </div>
                </body>
                </html>
                """
            
            # Attach HTML version
            email.attach(MIMEText(html_content, "html"))
            
            # Send the email
            for attempt in range(self.max_retries):
                try:
                    with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                        if self.use_tls:
                            server.starttls()
                        
                        # Authenticate if credentials provided
                        if self.username and self.password:
                            server.login(self.username, self.password)
                        
                        # Combine all recipients
                        all_recipients = self.to_addresses + self.cc_addresses + self.bcc_addresses
                        
                        # Send the email
                        server.send_message(email)
                        
                        logger.info(f"Successfully sent email notification: {title}")
                        return True
                        
                except Exception as e:
                    logger.warning(f"Error sending email (attempt {attempt+1}/{self.max_retries}): {e}")
                    time.sleep(1)  # Wait before retrying
            
            logger.error(f"Failed to send email notification after {self.max_retries} attempts: {title}")
            return False
            
        except Exception as e:
            logger.error(f"Error creating email notification: {e}")
            return False
    
    def send_batch(self, notifications: List[Dict[str, Any]]) -> List[bool]:
        """
        Send a batch of notifications via email
        
        Args:
            notifications: List of notification data dictionaries
            
        Returns:
            List of success status for each notification
        """
        results = []
        
        for notification in notifications:
            success = self.send_notification(
                title=notification.get("title", "IDS Alert"),
                message=notification.get("message", ""),
                data=notification.get("data"),
                severity=notification.get("severity", "medium"),
                tags=notification.get("tags")
            )
            results.append(success)
            
            # Add a small delay to avoid overwhelming the SMTP server
            time.sleep(0.5)
        
        return results

class PagerDutyNotifier(Notifier):
    """Sends notifications to PagerDuty"""
    
    def __init__(self,
                api_key: str,
                timeout: float = 10.0,
                max_retries: int = 3,
                service_id: Optional[str] = None,
                source: str = "IDS",
                component: str = "Security",
                include_full_data: bool = False):
        """
        Initialize PagerDuty notifier
        
        Args:
            api_key: PagerDuty API key or integration key
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            service_id: PagerDuty service ID
            source: Source of the event
            component: Component of the event
            include_full_data: Whether to include full alert data in notification
        """
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.service_id = service_id
        self.source = source
        self.component = component
        self.include_full_data = include_full_data
        
        # Initialize HTTP session
        self.session = None
        try:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                "Content-Type": "application/json",
                "Accept": "application/json"
            })
            logger.info("Initialized PagerDuty notifier")
        except ImportError:
            logger.error("requests package not found. Install with: pip install requests")
    
    def send_notification(self, 
                         title: str, 
                         message: str, 
                         data: Optional[Dict[str, Any]] = None, 
                         severity: str = "medium",
                         tags: Optional[List[str]] = None) -> bool:
        """
        Send a notification to PagerDuty
        
        Args:
            title: Title of the notification
            message: Message body
            data: Additional data to include in the notification
            severity: Severity of the alert (low, medium, high, critical)
            tags: Tags to include in the notification
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session:
            logger.error("PagerDuty session not initialized")
            return False
        
        try:
            # Map severity to PagerDuty urgency
            urgency_map = {
                "low": "low",
                "medium": "low",
                "high": "high",
                "critical": "high"
            }
            urgency = urgency_map.get(severity.lower(), "low")
            
            # Create a unique incident key based on title and timestamp
            incident_key = f"ids-{int(datetime.now().timestamp())}-{title[:20].replace(' ', '-')}"
            
            # Prepare event payload - using Events API v2
            payload = {
                "routing_key": self.api_key,
                "event_action": "trigger",
                "dedup_key": incident_key,
                "payload": {
                    "summary": title,
                    "source": self.source,
                    "severity": severity.lower(),  # PagerDuty uses critical, error, warning, info
                    "component": self.component,
                    "custom_details": {
                        "message": message
                    }
                }
            }
            
            # Add tags if provided
            if tags:
                payload["payload"]["custom_details"]["tags"] = tags
            
            # Add additional data if provided and inclusion is enabled
            if data and self.include_full_data:
                for key, value in data.items():
                    # Skip large or complex objects
                    if isinstance(value, (str, int, float, bool)) or (isinstance(value, list) and len(value) < 5):
                        payload["payload"]["custom_details"][key] = value
            
            # Send to PagerDuty
            for attempt in range(self.max_retries):
                response = self.session.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    timeout=self.timeout
                )
                
                if response.status_code == 202:
                    result = response.json()
                    if "status" in result and result["status"] == "success":
                        logger.info(f"Successfully sent PagerDuty notification: {title}")
                        return True
                
                logger.warning(f"Failed to send PagerDuty notification (attempt {attempt+1}/{self.max_retries}): {response.status_code} - {response.text}")
                time.sleep(1)  # Wait before retrying
            
            logger.error(f"Failed to send PagerDuty notification after {self.max_retries} attempts: {title}")
            return False
            
        except Exception as e:
            logger.error(f"Error sending PagerDuty notification: {e}")
            return False
    
    def send_batch(self, notifications: List[Dict[str, Any]]) -> List[bool]:
        """
        Send a batch of notifications to PagerDuty
        
        Args:
            notifications: List of notification data dictionaries
            
        Returns:
            List of success status for each notification
        """
        if not self.session:
            logger.error("PagerDuty session not initialized")
            return [False] * len(notifications)
        
        results = []
        
        # Use ThreadPoolExecutor for parallel processing
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Create notification tasks
            tasks = []
            for notification in notifications:
                tasks.append(executor.submit(
                    self.send_notification,
                    title=notification.get("title", "IDS Alert"),
                    message=notification.get("message", ""),
                    data=notification.get("data"),
                    severity=notification.get("severity", "medium"),
                    tags=notification.get("tags")
                ))
            
            # Collect results
            for task in concurrent.futures.as_completed(tasks):
                results.append(task.result())
        
        return results

class NotificationManager:
    """Manages multiple notification providers"""
    
    def __init__(self):
        """Initialize the notification manager"""
        self.notifiers = {}
        self._lock = threading.Lock()
    
    def add_notifier(self, name: str, notifier: Notifier) -> None:
        """
        Add a notifier
        
        Args:
            name: Name of the notifier
            notifier: Notifier instance
        """
        with self._lock:
            self.notifiers[name] = notifier
    
    def remove_notifier(self, name: str) -> None:
        """
        Remove a notifier
        
        Args:
            name: Name of the notifier
        """
        with self._lock:
            if name in self.notifiers:
                del self.notifiers[name]
    
    def get_notifier(self, name: str) -> Optional[Notifier]:
        """
        Get a notifier by name
        
        Args:
            name: Name of the notifier
            
        Returns:
            Notifier instance or None if not found
        """
        return self.notifiers.get(name)
    
    def send_notification(self, 
                         title: str, 
                         message: str, 
                         data: Optional[Dict[str, Any]] = None, 
                         severity: str = "medium",
                         tags: Optional[List[str]] = None,
                         notifiers: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Send a notification through specified notifiers
        
        Args:
            title: Title of the notification
            message: Message body
            data: Additional data to include in the notification
            severity: Severity of the alert (low, medium, high, critical)
            tags: Tags to include in the notification
            notifiers: List of notifier names to use (if None, use all)
            
        Returns:
            Dictionary of notifier name to success status
        """
        results = {}
        
        # Determine which notifiers to use
        if notifiers:
            notifiers_to_use = {name: self.notifiers[name] for name in notifiers if name in self.notifiers}
        else:
            notifiers_to_use = self.notifiers
        
        # Send notification through each notifier
        for name, notifier in notifiers_to_use.items():
            try:
                success = notifier.send_notification(title, message, data, severity, tags)
                results[name] = success
            except Exception as e:
                logger.error(f"Error sending notification with {name}: {e}")
                results[name] = False
        
        return results
    
    def send_batch(self, 
                  notifications: List[Dict[str, Any]],
                  notifiers: Optional[List[str]] = None) -> Dict[str, List[bool]]:
        """
        Send a batch of notifications through specified notifiers
        
        Args:
            notifications: List of notification data dictionaries
            notifiers: List of notifier names to use (if None, use all)
            
        Returns:
            Dictionary of notifier name to list of success status
        """
        results = {}
        
        # Determine which notifiers to use
        if notifiers:
            notifiers_to_use = {name: self.notifiers[name] for name in notifiers if name in self.notifiers}
        else:
            notifiers_to_use = self.notifiers
        
        # Send notifications through each notifier
        for name, notifier in notifiers_to_use.items():
            try:
                batch_results = notifier.send_batch(notifications)
                results[name] = batch_results
            except Exception as e:
                logger.error(f"Error sending batch notification with {name}: {e}")
                results[name] = [False] * len(notifications)
        
        return results 