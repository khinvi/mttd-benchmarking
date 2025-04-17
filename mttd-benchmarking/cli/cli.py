#!/usr/bin/env python3
"""
Command-line interface for the MTTD Benchmarking Framework.
"""

import argparse
import logging
import json
import os
import sys
import time
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..scenario.manager import ScenarioManager
from ..core.utils import setup_logging, load_config, configure_logging


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="MTTD Benchmarking Framework CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available scenarios
  python -m mttd_benchmarking.cli.cli list
  
  # Execute a specific scenario
  python -m mttd_benchmarking.cli.cli execute --scenario-id aws-privilege-escalation-001
  
  # Execute a benchmark across multiple scenarios and services
  python -m mttd_benchmarking.cli.cli benchmark --scenarios aws-privilege-escalation-001,aws-data-exfiltration-001 --services aws_guardduty,aws_securityhub
  
  # Generate a detailed report from benchmark results
  python -m mttd_benchmarking.cli.cli report --report-id 123e4567-e89b-12d3-a456-426614174000 --format html
"""
    )
    
    # Common arguments
    parser.add_argument(
        "--config", 
        type=str, 
        default="config/config.json",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--log-level", 
        type=str, 
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level"
    )
    
    parser.add_argument(
        "--log-file", 
        type=str, 
        help="Path to log file"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # List scenarios
    list_parser = subparsers.add_parser("list", help="List available scenarios")
    
    # Execute scenario
    exec_parser = subparsers.add_parser("execute", help="Execute a scenario")
    exec_parser.add_argument(
        "--scenario-id", 
        type=str, 
        required=True,
        help="ID of the scenario to execute"
    )
    exec_parser.add_argument(
        "--service",
        type=str,
        help="Override the service specified in the scenario"
    )
    
    # Execute benchmark
    benchmark_parser = subparsers.add_parser("benchmark", help="Execute a benchmark")
    benchmark_parser.add_argument(
        "--scenarios", 
        type=str, 
        required=True,
        help="Comma-separated list of scenario IDs"
    )
    benchmark_parser.add_argument(
        "--services", 
        type=str,
        help="Comma-separated list of service names"
    )
    
    # Generate reports
    report_parser = subparsers.add_parser("report", help="Generate a report from benchmark results")
    report_parser.add_argument(
        "--report-id",
        type=str,
        required=True,
        help="ID of the benchmark report to use"
    )
    report_parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv", "html", "markdown"],
        default="html",
        help="Report format"
    )
    
    # Create scenario
    create_parser = subparsers.add_parser("create", help="Create a new scenario")
    create_parser.add_argument(
        "--file",
        type=str,
        required=True,
        help="Path to JSON file with scenario definition"
    )
    
    # Validate scenario
    validate_parser = subparsers.add_parser("validate", help="Validate a scenario")
    validate_parser.add_argument(
        "--file",
        type=str,
        required=True,
        help="Path to JSON file with scenario definition"
    )
    
    return parser.parse_args()


def command_list(manager: ScenarioManager) -> None:
    """
    List available scenarios.
    
    Args:
        manager: Scenario manager instance
    """
    scenarios = manager.list_available_scenarios()
    
    if not scenarios:
        print("No scenarios found.")
        return
    
    print(f"Available scenarios ({len(scenarios)}):")
    print()
    print(f"{'ID':<30} | {'Name':<40} | {'Provider':<10} | {'Service':<20}")
    print("-" * 105)
    
    for scenario in scenarios:
        print(f"{scenario['id']:<30} | {scenario['name']:<40} | {scenario['provider']:<10} | {scenario['service']:<20}")


def command_execute(manager: ScenarioManager, scenario_id: str, service: Optional[str] = None) -> None:
    """
    Execute a scenario.
    
    Args:
        manager: Scenario manager instance
        scenario_id: ID of the scenario to execute
        service: Optional service override
    """
    print(f"Executing scenario {scenario_id}...")
    start_time = time.time()
    
    try:
        result = manager.execute_scenario(scenario_id, service_override=service)
        
        execution_time = time.time() - start_time
        print(f"\nExecution completed in {execution_time:.2f} seconds.")
        print(f"\nResults:")
        print(f"  Scenario: {result['scenario']['name']} ({result['scenario']['id']})")
        print(f"  Provider: {result['scenario']['provider']}")
        print(f"  Service: {result['scenario']['service']}")
        print(f"  Simulation ID: {result['simulation']['id']}")
        print(f"  Status: {result['simulation']['status']}")
        print(f"  Execution time: {execution_time:.2f} seconds")
        print(f"  Steps executed: {result['simulation']['steps_executed']}")
        print(f"  Indicators generated: {result['simulation']['indicators_generated']}")
        print()
        print(f"  Metrics:")
        print(f"    MTTD: {result['metrics']['mttd']:.2f} seconds" if result['metrics']['mttd'] >= 0 else "    MTTD: N/A")
        print(f"    Detection rate: {result['metrics']['detection_rate']*100:.2f}%")
        print(f"    False positives: {result['metrics']['false_positives']}")
        
    except Exception as e:
        print(f"Execution failed: {str(e)}")
        sys.exit(1)


def command_benchmark(manager: ScenarioManager, scenario_ids: List[str], services: Optional[List[str]] = None) -> None:
    """
    Execute a benchmark.
    
    Args:
        manager: Scenario manager instance
        scenario_ids: List of scenario IDs to execute
        services: Optional list of services to test
    """
    print(f"Executing benchmark with {len(scenario_ids)} scenarios...")
    if services:
        print(f"Testing across {len(services)} services: {', '.join(services)}")
    
    start_time = time.time()
    
    try:
        result = manager.execute_benchmark(scenario_ids, services)
        
        execution_time = time.time() - start_time
        print(f"\nBenchmark completed in {execution_time:.2f} seconds.")
        print(f"\nResults:")
        print(f"  Report ID: {result['report_id']}")
        print(f"  Services compared: {', '.join(result['services_compared'])}")
        print(f"  Scenarios executed: {', '.join(result['scenarios_executed'])}")
        print(f"  Total executions: {result['execution_count']}")
        print()
        print(f"  Service Comparison:")
        
        # Print MTTD table
        print(f"\n    Mean Time To Detect (MTTD):")
        print(f"    {'Service':<20} | {'MTTD (seconds)':<15}")
        print(f"    {'-'*20} | {'-'*15}")
        for service, mttd in result['service_comparison']['mttd'].items():
            mttd_str = f"{mttd:.2f}" if mttd >= 0 else "N/A"
            print(f"    {service:<20} | {mttd_str:<15}")
        
        # Print Detection Rate table
        print(f"\n    Detection Rate:")
        print(f"    {'Service':<20} | {'Rate (%)':<10}")
        print(f"    {'-'*20} | {'-'*10}")
        for service, rate in result['service_comparison']['detection_rate'].items():
            print(f"    {service:<20} | {rate*100:.2f}%")
        
        # Print False Positive Rate table
        print(f"\n    False Positive Rate:")
        print(f"    {'Service':<20} | {'Rate (%)':<10}")
        print(f"    {'-'*20} | {'-'*10}")
        for service, rate in result['service_comparison']['false_positive_rate'].items():
            print(f"    {service:<20} | {rate*100:.2f}%")
        
    except Exception as e:
        print(f"Benchmark failed: {str(e)}")
        sys.exit(1)


def command_report(manager: ScenarioManager, report_id: str, format: str) -> None:
    """
    Generate a report from benchmark results.
    
    Args:
        manager: Scenario manager instance
        report_id: ID of the benchmark report to use
        format: Report format
    """
    print(f"Generating {format} report for benchmark {report_id}...")
    
    try:
        # Get benchmark report
        report = manager.get_benchmark_report(report_id)
        
        if not report:
            print(f"Benchmark report not found: {report_id}")
            sys.exit(1)
        
        # Generate report based on format
        if format == "html":
            # Use detailed report generator for HTML
            from ..reporting.generators import DetailedReportGenerator
            generator = DetailedReportGenerator(manager.config.get("reporting", {}))
            
            # Convert report dict to BenchmarkReport object
            from ..core.types import BenchmarkReport
            benchmark_report = BenchmarkReport(
                report_id=report["report_id"],
                generation_time=datetime.fromisoformat(report["generation_time"]),
                service_comparison=report["service_comparison"],
                scenario_results=report.get("scenario_results", {}),
                service_details=report["service_details"]
            )
            
            report_path = generator.generate_html_report(benchmark_report)
            print(f"HTML report generated: {report_path}")
            
        elif format == "markdown":
            # Use detailed report generator for Markdown
            from ..reporting.generators import DetailedReportGenerator
            generator = DetailedReportGenerator(manager.config.get("reporting", {}))
            
            # Convert report dict to BenchmarkReport object
            from ..core.types import BenchmarkReport
            benchmark_report = BenchmarkReport(
                report_id=report["report_id"],
                generation_time=datetime.fromisoformat(report["generation_time"]),
                service_comparison=report["service_comparison"],
                scenario_results=report.get("scenario_results", {}),
                service_details=report["service_details"]
            )
            
            report_path = generator.generate_markdown_report(benchmark_report)
            print(f"Markdown report generated: {report_path}")
            
        elif format == "csv":
            # CSV report is already generated during benchmark
            report_path = os.path.join(
                manager.config.get("reporting", {}).get("output_dir", "reports"),
                f"benchmark_{report_id}.csv"
            )
            
            if os.path.exists(report_path):
                print(f"CSV report found: {report_path}")
            else:
                print(f"CSV report not found. Generating new report...")
                # Convert report dict to BenchmarkReport object
                from ..core.types import BenchmarkReport
                benchmark_report = BenchmarkReport(
                    report_id=report["report_id"],
                    generation_time=datetime.fromisoformat(report["generation_time"]),
                    service_comparison=report["service_comparison"],
                    scenario_results=report.get("scenario_results", {}),
                    service_details=report["service_details"]
                )
                
                # Generate CSV report
                report_path = manager.report_generator._export_csv_report(benchmark_report)
                print(f"CSV report generated: {report_path}")
                
        elif format == "json":
            # JSON report is already generated during benchmark
            report_path = os.path.join(
                manager.config.get("reporting", {}).get("output_dir", "reports"),
                f"benchmark_{report_id}.json"
            )
            
            if os.path.exists(report_path):
                print(f"JSON report found: {report_path}")
            else:
                print(f"JSON report not found. Using original report data.")
                report_path = os.path.join(
                    manager.config.get("reporting", {}).get("output_dir", "reports"),
                    f"benchmark_{report_id}_new.json"
                )
                
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2)
                    
                print(f"JSON report generated: {report_path}")
        
    except Exception as e:
        print(f"Report generation failed: {str(e)}")
        sys.exit(1)


def command_create(manager: ScenarioManager, file_path: str) -> None:
    """
    Create a new scenario from a JSON file.
    
    Args:
        manager: Scenario manager instance
        file_path: Path to JSON file with scenario definition
    """
    print(f"Creating new scenario from {file_path}...")
    
    try:
        # Read scenario file
        with open(file_path, 'r') as f:
            scenario_data = json.load(f)
        
        # Create scenario
        scenario_id = manager.create_scenario(scenario_data)
        
        print(f"Scenario created with ID: {scenario_id}")
        
    except Exception as e:
        print(f"Scenario creation failed: {str(e)}")
        sys.exit(1)


def command_validate(manager: ScenarioManager, file_path: str) -> None:
    """
    Validate a scenario file.
    
    Args:
        manager: Scenario manager instance
        file_path: Path to JSON file with scenario definition
    """
    print(f"Validating scenario {file_path}...")
    
    try:
        # Validate scenario file
        validation_result = manager.validator.validate_scenario_file(file_path)
        
        if validation_result["valid"]:
            print("Scenario is valid!")
        else:
            print("Scenario validation failed:")
            for error in validation_result["errors"]:
                print(f"  - {error}")
            sys.exit(1)
        
    except Exception as e:
        print(f"Validation failed: {str(e)}")
        sys.exit(1)


def main() -> None:
    """Main entry point for the CLI."""
    args = parse_args()
    
    # Set up logging
    configure_logging(
        log_level=args.log_level,
        log_file=args.log_file
    )
    
    # Load configuration
    try:
        config = load_config(args.config)
    except Exception as e:
        logging.error(f"Failed to load configuration: {str(e)}")
        sys.exit(1)
    
    # Initialize scenario manager
    manager = ScenarioManager(config)
    
    # Execute command
    if args.command == "list":
        command_list(manager)
    
    elif args.command == "execute":
        command_execute(manager, args.scenario_id, args.service)
    
    elif args.command == "benchmark":
        scenario_ids = args.scenarios.split(",")
        services = args.services.split(",") if args.services else None
        command_benchmark(manager, scenario_ids, services)
    
    elif args.command == "report":
        command_report(manager, args.report_id, args.format)
    
    elif args.command == "create":
        command_create(manager, args.file)
    
    elif args.command == "validate":
        command_validate(manager, args.file)
    
    else:
        print("No command specified. Use --help for usage information.")


if __name__ == "__main__":
    main()