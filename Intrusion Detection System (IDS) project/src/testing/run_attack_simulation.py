#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Attack Simulation Runner Script
This script demonstrates how to use the attack simulation module.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add the project root directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Import attack simulation module
from src.testing.attack_simulation import (
    PortScanSimulator, DDoSSimulator, SQLInjectionSimulator, BruteForceSimulator,
    load_scenario_from_file, run_attack_scenario, demo
)

def setup_logging(log_level=logging.INFO):
    """Set up logging for the attack simulation."""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('attack_simulation.log')
        ]
    )

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Run attack simulations for IDS testing')
    
    # Define subparsers for different commands
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Run the attack simulation demo')
    
    # Scenario command
    scenario_parser = subparsers.add_parser('scenario', help='Run an attack scenario from a file')
    scenario_parser.add_argument('--file', '-f', required=True, help='Path to the scenario file')
    
    # Individual attack commands
    port_scan_parser = subparsers.add_parser('port-scan', help='Run a port scan simulation')
    port_scan_parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address')
    port_scan_parser.add_argument('--ports', '-p', nargs='+', type=int, default=[22, 80, 443, 3306, 5432],
                                 help='Ports to scan')
    port_scan_parser.add_argument('--scan-type', '-s', choices=['tcp_connect', 'syn_scan', 'fin_scan'],
                                 default='tcp_connect', help='Type of port scan')
    
    brute_force_parser = subparsers.add_parser('brute-force', help='Run a brute force attack simulation')
    brute_force_parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address')
    brute_force_parser.add_argument('--port', '-p', type=int, default=22, help='Target port')
    brute_force_parser.add_argument('--protocol', '-r', choices=['ssh', 'ftp', 'http'],
                                   default='ssh', help='Protocol to attack')
    brute_force_parser.add_argument('--username', '-u', default='admin', help='Username to try')
    
    ddos_parser = subparsers.add_parser('ddos', help='Run a DDoS attack simulation')
    ddos_parser.add_argument('--target', '-t', default='127.0.0.1', help='Target IP address')
    ddos_parser.add_argument('--port', '-p', type=int, default=80, help='Target port')
    ddos_parser.add_argument('--attack-type', '-a', choices=['syn_flood', 'http_flood', 'udp_flood'],
                            default='http_flood', help='Type of DDoS attack')
    ddos_parser.add_argument('--duration', '-d', type=int, default=10, help='Duration of attack in seconds')
    
    sql_injection_parser = subparsers.add_parser('sql-injection', help='Run a SQL injection attack simulation')
    sql_injection_parser.add_argument('--target', '-t', default='http://127.0.0.1', help='Target URL')
    sql_injection_parser.add_argument('--path', '-p', default='/login', help='Target path')
    sql_injection_parser.add_argument('--param', '-a', default='username', help='Parameter to inject')
    
    # Global arguments
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    return parser.parse_args()

def main():
    """Main entry point for the script."""
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    # Get the logger
    logger = logging.getLogger('ids.testing')
    
    # Run the appropriate command
    if args.command == 'demo':
        logger.info("Running attack simulation demo")
        demo()
    
    elif args.command == 'scenario':
        scenario_file = args.file
        logger.info(f"Running attack scenario from file: {scenario_file}")
        
        if not os.path.exists(scenario_file):
            logger.error(f"Scenario file not found: {scenario_file}")
            return 1
            
        scenario_config = load_scenario_from_file(scenario_file)
        if not scenario_config:
            logger.error(f"Failed to load scenario from file: {scenario_file}")
            return 1
            
        success = run_attack_scenario(scenario_config)
        if not success:
            logger.error("Attack scenario failed")
            return 1
    
    elif args.command == 'port-scan':
        logger.info(f"Running port scan simulation against {args.target}")
        config = {
            'target': args.target,
            'ports': args.ports,
            'scan_type': args.scan_type
        }
        simulator = PortScanSimulator(config)
        simulator.start()
        
        try:
            # Wait for user to press Ctrl+C
            logger.info("Press Ctrl+C to stop the simulation")
            while simulator.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping simulation...")
        finally:
            simulator.stop()
    
    elif args.command == 'brute-force':
        logger.info(f"Running brute force simulation against {args.target}:{args.port}")
        config = {
            'target': args.target,
            'target_port': args.port,
            'protocol': args.protocol,
            'username': args.username
        }
        simulator = BruteForceSimulator(config)
        simulator.start()
        
        try:
            # Wait for user to press Ctrl+C
            logger.info("Press Ctrl+C to stop the simulation")
            while simulator.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping simulation...")
        finally:
            simulator.stop()
    
    elif args.command == 'ddos':
        logger.info(f"Running DDoS simulation against {args.target}:{args.port}")
        config = {
            'target': args.target,
            'target_port': args.port,
            'attack_type': args.attack_type,
            'duration': args.duration
        }
        simulator = DDoSSimulator(config)
        simulator.start()
        
        try:
            # Wait for user to press Ctrl+C
            logger.info("Press Ctrl+C to stop the simulation")
            while simulator.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping simulation...")
        finally:
            simulator.stop()
    
    elif args.command == 'sql-injection':
        logger.info(f"Running SQL injection simulation against {args.target}{args.path}")
        config = {
            'target': args.target,
            'target_path': args.path,
            'param_name': args.param
        }
        simulator = SQLInjectionSimulator(config)
        simulator.start()
        
        try:
            # Wait for user to press Ctrl+C
            logger.info("Press Ctrl+C to stop the simulation")
            while simulator.running:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping simulation...")
        finally:
            simulator.stop()
    
    else:
        logger.error("No command specified")
        return 1
    
    logger.info("Attack simulation completed")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 