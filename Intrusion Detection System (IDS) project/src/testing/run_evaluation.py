#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
IDS Evaluation Runner Script
This script runs the IDS evaluation framework.
"""

import os
import sys
import argparse
import logging
import json
from pathlib import Path
from datetime import datetime

# Add the project root directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Import evaluation framework
from src.testing.evaluation_framework import (
    IDSEvaluator, create_controlled_environment, metasploit_integration
)

def setup_logging(log_level=logging.INFO, log_file=None):
    """Set up logging for the evaluation script."""
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run IDS evaluation tests')
    
    # Environment setup
    parser.add_argument('--env-config', '-e', type=str, 
                       help='Path to test environment configuration file')
    parser.add_argument('--setup-env', action='store_true',
                      help='Set up the controlled test environment')
    
    # Test scenario
    parser.add_argument('--scenario', '-s', type=str,
                       help='Path to the test scenario file')
    
    # Alert and event logs
    parser.add_argument('--alert-log', '-a', type=str,
                       help='Path to the IDS alert log file')
    parser.add_argument('--event-log', '-v', type=str,
                       help='Path to the attack events log file')
    
    # Output options
    parser.add_argument('--output', '-o', type=str,
                       help='Path to save the evaluation report')
    parser.add_argument('--format', '-f', choices=['json', 'yaml', 'txt'], default='json',
                      help='Format of the evaluation report')
    
    # Metasploit integration
    parser.add_argument('--metasploit', '-m', action='store_true',
                      help='Use Metasploit for penetration testing')
    parser.add_argument('--exploit', type=str,
                      help='Metasploit exploit to use')
    parser.add_argument('--target', '-t', type=str,
                      help='Target for Metasploit exploit')
    
    # Logging options
    parser.add_argument('--verbose', '-V', action='store_true',
                      help='Enable verbose logging')
    parser.add_argument('--log-file', '-l', type=str,
                       help='Path to save the log file')
    
    return parser.parse_args()

def main():
    """Main entry point for the script."""
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level, args.log_file)
    
    # Get the logger
    logger = logging.getLogger('ids.testing.evaluation')
    
    # Set up the controlled test environment if requested
    if args.setup_env:
        if not args.env_config:
            logger.error("Environment configuration file is required for setting up the environment")
            return 1
            
        logger.info("Setting up controlled test environment")
        env_result = create_controlled_environment(args.env_config)
        
        if env_result.get('status') != 'success':
            logger.error(f"Failed to set up environment: {env_result.get('message')}")
            return 1
            
        logger.info("Controlled test environment setup successful")
    
    # Use Metasploit for penetration testing if requested
    if args.metasploit:
        if not args.exploit or not args.target:
            logger.error("Both exploit and target are required for Metasploit integration")
            return 1
            
        logger.info(f"Running Metasploit exploit {args.exploit} against {args.target}")
        msf_result = metasploit_integration(args.target, args.exploit)
        
        logger.info(f"Metasploit result: {msf_result.get('status')}")
        
        if args.output:
            # Save Metasploit results to file
            msf_output_file = f"{os.path.splitext(args.output)[0]}_metasploit.json"
            try:
                with open(msf_output_file, 'w') as f:
                    json.dump(msf_result, f, indent=2)
                logger.info(f"Metasploit results saved to {msf_output_file}")
            except Exception as e:
                logger.error(f"Error saving Metasploit results: {e}")
    
    # Create evaluator
    evaluator = IDSEvaluator(args.env_config)
    
    # Run test scenario if specified
    if args.scenario:
        logger.info(f"Running test scenario from {args.scenario}")
        
        if not os.path.exists(args.scenario):
            logger.error(f"Scenario file not found: {args.scenario}")
            return 1
            
        success = evaluator.run_test_scenario(args.scenario)
        
        if not success:
            logger.error("Test scenario failed")
            return 1
            
        logger.info("Test scenario completed successfully")
    
    # Collect alerts if specified
    if args.alert_log:
        if not os.path.exists(args.alert_log):
            logger.warning(f"Alert log file not found: {args.alert_log}")
        else:
            num_alerts = evaluator.collect_alerts(args.alert_log)
            logger.info(f"Collected {num_alerts} alerts from {args.alert_log}")
    
    # Collect attack events if specified
    if args.event_log:
        if not os.path.exists(args.event_log):
            logger.warning(f"Event log file not found: {args.event_log}")
        else:
            num_events = evaluator.collect_attack_events(args.event_log)
            logger.info(f"Collected {num_events} attack events from {args.event_log}")
    
    # Match alerts to attack events if both are available
    if evaluator.alerts and evaluator.attack_events:
        logger.info("Matching alerts to attack events")
        match_results = evaluator.match_alerts_to_attacks()
        
        logger.info(f"Matching results: {match_results['true_positives']} true positives, "
                   f"{match_results['false_positives']} false positives, "
                   f"{match_results['false_negatives']} false negatives")
        logger.info(f"Precision: {match_results['precision']:.4f}, "
                   f"Recall: {match_results['recall']:.4f}, "
                   f"F1 Score: {match_results['f1_score']:.4f}")
    
    # Generate evaluation report
    logger.info("Generating evaluation report")
    
    # Determine output file path
    output_file = None
    if args.output:
        output_file = args.output
        
        # Add extension if not specified
        if args.format == 'json' and not output_file.endswith('.json'):
            output_file += '.json'
        elif args.format == 'yaml' and not output_file.endswith(('.yaml', '.yml')):
            output_file += '.yaml'
        elif args.format == 'txt' and not output_file.endswith('.txt'):
            output_file += '.txt'
    
    # Generate the report
    report = evaluator.generate_report(output_file)
    
    # Print the report to console if no output file specified
    if not args.output:
        if args.format == 'json':
            print(json.dumps(report, indent=2))
        elif args.format == 'yaml':
            import yaml
            print(yaml.dump(report, default_flow_style=False))
        elif args.format == 'txt':
            print("IDS EVALUATION REPORT")
            print("=====================")
            print(f"Generated: {report['timestamp']}")
            print()
            
            if 'scenario' in report and report['scenario']:
                print(f"Scenario: {report['scenario'].get('name', 'Unknown')}")
                print(f"Description: {report['scenario'].get('description', '')}")
                print(f"Duration: {report['scenario'].get('duration', 0)} seconds")
                print()
            
            if 'metrics' in report and report['metrics']:
                print("PERFORMANCE METRICS")
                print("------------------")
                print(f"True Positives: {report['metrics'].get('true_positives', 0)}")
                print(f"False Positives: {report['metrics'].get('false_positives', 0)}")
                print(f"False Negatives: {report['metrics'].get('false_negatives', 0)}")
                print(f"Precision: {report['metrics'].get('precision', 0):.4f}")
                print(f"Recall: {report['metrics'].get('recall', 0):.4f}")
                print(f"F1 Score: {report['metrics'].get('f1_score', 0):.4f}")
                print()
            
            if 'mitre' in report and report['mitre']:
                print("MITRE ATT&CK COVERAGE")
                print("--------------------")
                print(f"Tactics: {', '.join(report['mitre'].get('tactics', []))}")
                print(f"Technique Count: {report['mitre'].get('technique_count', 0)}")
                print()
                
                for technique in report['mitre'].get('techniques', []):
                    print(f"Technique: {technique.get('technique_id')} - {technique.get('technique_name')}")
                    print(f"Tactic: {technique.get('tactic')}")
                    print(f"Attack: {technique.get('attack_name')}")
                    print(f"URL: {technique.get('url')}")
                    print()
    
    logger.info("Evaluation completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 