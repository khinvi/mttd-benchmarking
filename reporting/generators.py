"""
Report generators for creating benchmark reports.
"""

import logging
import uuid
import json
import os
import csv
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

from ..core.types import MetricsResult, SimulationResult, BenchmarkReport

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates comprehensive reports and visualizations from metrics data.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the report generator.
        
        Args:
            config: Configuration for the report generator
        """
        self.config = config
        self.output_dir = config.get("output_dir", "reports")
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_benchmark_report(
        self, 
        metrics_results: List[MetricsResult],
        simulation_results: List[SimulationResult],
        service_details: Dict[str, Dict]
    ) -> BenchmarkReport:
        """
        Generate a comprehensive benchmark report from multiple metrics results.
        
        Args:
            metrics_results: List of metrics results from different simulations
            simulation_results: List of simulation results
            service_details: Information about the services being benchmarked
            
        Returns:
            BenchmarkReport with comparative analysis
        """
        logger.info(f"Generating benchmark report for {len(metrics_results)} metrics results")
        
        # Map simulations to their services
        simulation_to_service = {}
        for sim_result in simulation_results:
            # Find corresponding metrics for this simulation
            for metrics in metrics_results:
                if metrics.simulation_id == sim_result.simulation_id:
                    simulation_to_service[sim_result.simulation_id] = metrics.service_name
                    break
        
        # Group metrics by service
        service_metrics = {}
        for metrics in metrics_results:
            service_name = metrics.service_name
            if service_name not in service_metrics:
                service_metrics[service_name] = []
            service_metrics[service_name].append(metrics)
        
        # Calculate comparative metrics
        service_mttds = {}
        service_detection_rates = {}
        service_false_positive_rates = {}
        
        for service_name, metrics_list in service_metrics.items():
            # Calculate average MTTD for service
            valid_mttds = [m.mttd for m in metrics_list if m.mttd >= 0]
            if valid_mttds:
                service_mttds[service_name] = sum(valid_mttds) / len(valid_mttds)
            else:
                service_mttds[service_name] = -1
                
            # Calculate average detection rate
            service_detection_rates[service_name] = sum(m.detection_rate for m in metrics_list) / len(metrics_list)
            
            # Calculate false positive rate
            total_detections = sum(len(m.alerts_matched) for m in metrics_list)
            total_false_positives = sum(m.false_positives for m in metrics_list)
            
            if total_detections + total_false_positives > 0:
                service_false_positive_rates[service_name] = total_false_positives / (total_detections + total_false_positives)
            else:
                service_false_positive_rates[service_name] = 0
        
        # Create scenario results
        scenario_results = {}
        for metrics in metrics_results:
            scenario_id = metrics.scenario_id
            service_name = metrics.service_name
            
            if scenario_id not in scenario_results:
                scenario_results[scenario_id] = {
                    "services": {}
                }
            
            scenario_results[scenario_id]["services"][service_name] = {
                "mttd": metrics.mttd,
                "detection_rate": metrics.detection_rate,
                "false_positives": metrics.false_positives
            }
        
        # Create benchmark report
        report = BenchmarkReport(
            report_id=str(uuid.uuid4()),
            generation_time=datetime.now(),
            service_comparison={
                "mttd": service_mttds,
                "detection_rate": service_detection_rates,
                "false_positive_rate": service_false_positive_rates
            },
            scenario_results=scenario_results,
            service_details=service_details,
            raw_metrics=metrics_results
        )
        
        # Generate report files
        self._export_csv_report(report)
        self._export_json_report(report)
        
        logger.info(f"Benchmark report generated with ID: {report.report_id}")
        return report
    
    def _export_csv_report(self, report: BenchmarkReport) -> str:
        """
        Export benchmark results to CSV format.
        
        Args:
            report: The benchmark report
            
        Returns:
            Path to the exported CSV file
        """
        csv_path = os.path.join(self.output_dir, f"benchmark_{report.report_id}.csv")
        
        with open(csv_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Service', 'MTTD (seconds)', 'Detection Rate (%)', 'False Positive Rate (%)'])
            
            # Write service comparison data
            for service_name in report.service_comparison["mttd"].keys():
                mttd = report.service_comparison["mttd"][service_name]
                detection_rate = report.service_comparison["detection_rate"][service_name] * 100
                fp_rate = report.service_comparison["false_positive_rate"][service_name] * 100
                
                writer.writerow([
                    service_name,
                    f"{mttd:.2f}" if mttd >= 0 else "N/A",
                    f"{detection_rate:.2f}",
                    f"{fp_rate:.2f}"
                ])
                
            # Add a blank row
            writer.writerow([])
            
            # Write details by scenario
            writer.writerow(['Scenario', 'Service', 'MTTD (seconds)', 'Detection Rate (%)', 'False Positives'])
            
            for scenario_id, scenario_data in report.scenario_results.items():
                for service_name, service_data in scenario_data["services"].items():
                    mttd = service_data["mttd"]
                    detection_rate = service_data["detection_rate"] * 100
                    false_positives = service_data["false_positives"]
                    
                    writer.writerow([
                        scenario_id,
                        service_name,
                        f"{mttd:.2f}" if mttd >= 0 else "N/A",
                        f"{detection_rate:.2f}",
                        false_positives
                    ])
                
        logger.info(f"CSV report exported to {csv_path}")
        return csv_path
    
    def _export_json_report(self, report: BenchmarkReport) -> str:
        """
        Export benchmark results to JSON format.
        
        Args:
            report: The benchmark report
            
        Returns:
            Path to the exported JSON file
        """
        json_path = os.path.join(self.output_dir, f"benchmark_{report.report_id}.json")
        
        # Convert report to dictionary
        report_dict = {
            "report_id": report.report_id,
            "generation_time": report.generation_time.isoformat(),
            "service_comparison": report.service_comparison,
            "scenario_results": report.scenario_results,
            "service_details": report.service_details
        }
        
        with open(json_path, 'w') as jsonfile:
            json.dump(report_dict, jsonfile, indent=2)
            
        logger.info(f"JSON report exported to {json_path}")
        return json_path
    
    def generate_single_service_report(
        self,
        metrics_results: List[MetricsResult],
        service_name: str
    ) -> Dict[str, Any]:
        """
        Generate a detailed report for a single security service.
        
        Args:
            metrics_results: List of metrics results for the service
            service_name: Name of the service
            
        Returns:
            Dictionary with detailed service report
        """
        if not metrics_results:
            logger.warning(f"No metrics results provided for service {service_name}")
            return {
                "service_name": service_name,
                "report_id": str(uuid.uuid4()),
                "generation_time": datetime.now().isoformat(),
                "metrics_count": 0,
                "summary": {
                    "mttd": -1,
                    "detection_rate": 0,
                    "false_positive_rate": 0
                },
                "scenarios": []
            }
        
        # Filter metrics for the specified service
        service_metrics = [m for m in metrics_results if m.service_name == service_name]
        
        if not service_metrics:
            logger.warning(f"No metrics found for service {service_name}")
            return {
                "service_name": service_name,
                "report_id": str(uuid.uuid4()),
                "generation_time": datetime.now().isoformat(),
                "metrics_count": 0,
                "summary": {
                    "mttd": -1,
                    "detection_rate": 0,
                    "false_positive_rate": 0
                },
                "scenarios": []
            }
        
        # Calculate summary metrics
        valid_mttds = [m.mttd for m in service_metrics if m.mttd >= 0]
        avg_mttd = sum(valid_mttds) / len(valid_mttds) if valid_mttds else -1
        avg_detection_rate = sum(m.detection_rate for m in service_metrics) / len(service_metrics)
        
        total_detections = sum(len(m.alerts_matched) for m in service_metrics)
        total_false_positives = sum(m.false_positives for m in service_metrics)
        
        if total_detections + total_false_positives > 0:
            false_positive_rate = total_false_positives / (total_detections + total_false_positives)
        else:
            false_positive_rate = 0
        
        # Group by scenario
        scenarios = {}
        for metrics in service_metrics:
            scenario_id = metrics.scenario_id
            
            if scenario_id not in scenarios:
                scenarios[scenario_id] = {
                    "scenario_id": scenario_id,
                    "executions": []
                }
            
            scenarios[scenario_id]["executions"].append({
                "simulation_id": metrics.simulation_id,
                "metrics_id": metrics.metrics_id,
                "mttd": metrics.mttd,
                "detection_rate": metrics.detection_rate,
                "false_positives": metrics.false_positives,
                "severity_distribution": metrics.severity_distribution,
                "calculation_time": metrics.calculation_time.isoformat()
            })
        
        # Create service report
        report = {
            "service_name": service_name,
            "report_id": str(uuid.uuid4()),
            "generation_time": datetime.now().isoformat(),
            "metrics_count": len(service_metrics),
            "summary": {
                "mttd": avg_mttd,
                "detection_rate": avg_detection_rate,
                "false_positive_rate": false_positive_rate,
                "total_detections": total_detections,
                "total_false_positives": total_false_positives
            },
            "scenarios": list(scenarios.values())
        }
        
        # Export to JSON
        json_path = os.path.join(self.output_dir, f"service_{service_name}_{report['report_id']}.json")
        
        with open(json_path, 'w') as jsonfile:
            json.dump(report, jsonfile, indent=2)
            
        logger.info(f"Service report for {service_name} exported to {json_path}")
        
        return report
    
    def generate_visualization_data(self, benchmark_report: BenchmarkReport) -> Dict[str, Any]:
        """
        Generate data for visualizations.
        
        Args:
            benchmark_report: The benchmark report
            
        Returns:
            Dictionary with visualization data
        """
        visualization_data = {
            "mttd_comparison": [],
            "detection_rate_comparison": [],
            "false_positive_comparison": [],
            "service_summary": []
        }
        
        # Prepare MTTD comparison data
        for service, mttd in benchmark_report.service_comparison["mttd"].items():
            if mttd >= 0:  # Only include valid MTTDs
                visualization_data["mttd_comparison"].append({
                    "service": service,
                    "mttd": mttd
                })
        
        # Prepare detection rate comparison data
        for service, rate in benchmark_report.service_comparison["detection_rate"].items():
            visualization_data["detection_rate_comparison"].append({
                "service": service,
                "rate": rate * 100  # Convert to percentage
            })
        
        # Prepare false positive rate comparison data
        for service, rate in benchmark_report.service_comparison["false_positive_rate"].items():
            visualization_data["false_positive_comparison"].append({
                "service": service,
                "rate": rate * 100  # Convert to percentage
            })
        
        # Prepare service summary data
        for service in benchmark_report.service_comparison["mttd"].keys():
            mttd = benchmark_report.service_comparison["mttd"][service]
            detection_rate = benchmark_report.service_comparison["detection_rate"][service] * 100
            fp_rate = benchmark_report.service_comparison["false_positive_rate"][service] * 100
            
            service_type = benchmark_report.service_details.get(service, {}).get("type", "unknown")
            provider = benchmark_report.service_details.get(service, {}).get("provider", "unknown")
            
            visualization_data["service_summary"].append({
                "service": service,
                "mttd": mttd if mttd >= 0 else None,
                "detection_rate": detection_rate,
                "false_positive_rate": fp_rate,
                "type": service_type,
                "provider": provider
            })
        
        # Export visualization data to JSON
        json_path = os.path.join(self.output_dir, f"viz_{benchmark_report.report_id}.json")
        
        with open(json_path, 'w') as jsonfile:
            json.dump(visualization_data, jsonfile, indent=2)
            
        logger.info(f"Visualization data exported to {json_path}")
        
        return visualization_data


class DetailedReportGenerator(ReportGenerator):
    """
    Generates more detailed reports with advanced metrics and visualizations.
    Extends the base ReportGenerator with additional capabilities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the detailed report generator.
        
        Args:
            config: Configuration for the report generator
        """
        super().__init__(config)
        self.template_dir = config.get("template_dir", "templates")
    
    def generate_html_report(self, benchmark_report: BenchmarkReport) -> str:
        """
        Generate an HTML report with interactive visualizations.
        
        Args:
            benchmark_report: The benchmark report
            
        Returns:
            Path to the generated HTML report
        """
        # Generate visualization data
        viz_data = self.generate_visualization_data(benchmark_report)
        
        # Create HTML file path
        html_path = os.path.join(self.output_dir, f"report_{benchmark_report.report_id}.html")
        
        # Load HTML template
        template_path = os.path.join(self.template_dir, "report_template.html")
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                template = f.read()
        else:
            # Create a basic template if none exists
            template = self._create_basic_html_template()
        
        # Replace placeholders with actual data
        report_html = template.replace(
            "{{REPORT_ID}}", benchmark_report.report_id
        ).replace(
            "{{GENERATION_TIME}}", benchmark_report.generation_time.strftime("%Y-%m-%d %H:%M:%S")
        ).replace(
            "{{VISUALIZATION_DATA}}", json.dumps(viz_data)
        )
        
        # Write HTML file
        with open(html_path, 'w') as f:
            f.write(report_html)
            
        logger.info(f"HTML report generated at {html_path}")
        
        return html_path
    
    def _create_basic_html_template(self) -> str:
        """
        Create a basic HTML template for reports.
        
        Returns:
            HTML template string
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MTTD Benchmark Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .report-container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .chart-container {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .chart {
            width: 48%;
            margin-bottom: 20px;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 0 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <h1>MTTD Benchmark Report</h1>
            <p>Report ID: {{REPORT_ID}}</p>
            <p>Generated: {{GENERATION_TIME}}</p>
        </div>
        
        <h2>Service Comparison</h2>
        <div class="chart-container">
            <div class="chart">
                <h3>Mean Time To Detect (MTTD)</h3>
                <canvas id="mttdChart"></canvas>
            </div>
            <div class="chart">
                <h3>Detection Rate</h3>
                <canvas id="detectionRateChart"></canvas>
            </div>
            <div class="chart">
                <h3>False Positive Rate</h3>
                <canvas id="falsePositiveChart"></canvas>
            </div>
            <div class="chart">
                <h3>Overall Comparison</h3>
                <canvas id="radarChart"></canvas>
            </div>
        </div>
        
        <h2>Service Summary</h2>
        <table id="serviceSummaryTable">
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Provider</th>
                    <th>Type</th>
                    <th>MTTD (seconds)</th>
                    <th>Detection Rate (%)</th>
                    <th>False Positive Rate (%)</th>
                </tr>
            </thead>
            <tbody id="serviceSummaryBody">
                <!-- Table rows will be generated dynamically -->
            </tbody>
        </table>
    </div>
    
    <script>
        // Visualization data
        const vizData = {{VISUALIZATION_DATA}};
        
        // Render charts
        document.addEventListener('DOMContentLoaded', function() {
            // MTTD Chart
            const mttdCtx = document.getElementById('mttdChart').getContext('2d');
            new Chart(mttdCtx, {
                type: 'bar',
                data: {
                    labels: vizData.mttd_comparison.map(item => item.service),
                    datasets: [{
                        label: 'MTTD (seconds)',
                        data: vizData.mttd_comparison.map(item => item.mttd),
                        backgroundColor: 'rgba(54, 162, 235, 0.5)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Seconds'
                            }
                        }
                    }
                }
            });
            
            // Detection Rate Chart
            const detectionRateCtx = document.getElementById('detectionRateChart').getContext('2d');
            new Chart(detectionRateCtx, {
                type: 'bar',
                data: {
                    labels: vizData.detection_rate_comparison.map(item => item.service),
                    datasets: [{
                        label: 'Detection Rate (%)',
                        data: vizData.detection_rate_comparison.map(item => item.rate),
                        backgroundColor: 'rgba(75, 192, 192, 0.5)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            title: {
                                display: true,
                                text: 'Percentage (%)'
                            }
                        }
                    }
                }
            });
            
            // False Positive Rate Chart
            const fpCtx = document.getElementById('falsePositiveChart').getContext('2d');
            new Chart(fpCtx, {
                type: 'bar',
                data: {
                    labels: vizData.false_positive_comparison.map(item => item.service),
                    datasets: [{
                        label: 'False Positive Rate (%)',
                        data: vizData.false_positive_comparison.map(item => item.rate),
                        backgroundColor: 'rgba(255, 99, 132, 0.5)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            title: {
                                display: true,
                                text: 'Percentage (%)'
                            }
                        }
                    }
                }
            });
            
            // Populate service summary table
            const tableBody = document.getElementById('serviceSummaryBody');
            vizData.service_summary.forEach(service => {
                const row = document.createElement('tr');
                
                row.innerHTML = `
                    <td>${service.service}</td>
                    <td>${service.provider}</td>
                    <td>${service.type}</td>
                    <td>${service.mttd !== null ? service.mttd.toFixed(2) : 'N/A'}</td>
                    <td>${service.detection_rate.toFixed(2)}</td>
                    <td>${service.false_positive_rate.toFixed(2)}</td>
                `;
                
                tableBody.appendChild(row);
            });
            
            // Radar Chart for overall comparison
            const radarCtx = document.getElementById('radarChart').getContext('2d');
            new Chart(radarCtx, {
                type: 'radar',
                data: {
                    labels: ['Detection Rate', 'Speed (inverse MTTD)', 'Accuracy (inverse FP)'],
                    datasets: vizData.service_summary.map((service, index) => {
                        // Calculate normalized values
                        const detectionRate = service.detection_rate / 100;
                        const mttdValue = service.mttd !== null ? 
                            Math.max(0, 1 - (service.mttd / 3600)) : 0; // Normalize: lower is better
                        const fpValue = Math.max(0, 1 - (service.false_positive_rate / 100)); // Normalize: lower is better
                        
                        // Generate a color based on index
                        const hue = (index * 137) % 360;
                        const color = `hsl(${hue}, 70%, 60%)`;
                        
                        return {
                            label: service.service,
                            data: [detectionRate, mttdValue, fpValue],
                            backgroundColor: `${color}33`,
                            borderColor: color,
                            borderWidth: 2,
                            pointBackgroundColor: color
                        };
                    })
                },
                options: {
                    scales: {
                        r: {
                            angleLines: {
                                display: true
                            },
                            ticks: {
                                beginAtZero: true,
                                max: 1,
                                stepSize: 0.2
                            }
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>
"""
    
    def generate_markdown_report(self, benchmark_report: BenchmarkReport) -> str:
        """
        Generate a Markdown report.
        
        Args:
            benchmark_report: The benchmark report
            
        Returns:
            Path to the generated Markdown report
        """
        md_path = os.path.join(self.output_dir, f"report_{benchmark_report.report_id}.md")
        
        # Format timestamp
        timestamp = benchmark_report.generation_time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Build Markdown content
        md_content = f"""# MTTD Benchmark Report

## Overview
- **Report ID:** {benchmark_report.report_id}
- **Generated:** {timestamp}
- **Services Compared:** {", ".join(benchmark_report.service_comparison["mttd"].keys())}

## Service Comparison

### Mean Time To Detect (MTTD)

| Service | MTTD (seconds) |
|---------|----------------|
"""
        
        # Add MTTD data
        for service, mttd in benchmark_report.service_comparison["mttd"].items():
            mttd_str = f"{mttd:.2f}" if mttd >= 0 else "N/A"
            md_content += f"| {service} | {mttd_str} |\n"
        
        # Add Detection Rate section
        md_content += """
### Detection Rate

| Service | Detection Rate (%) |
|---------|-------------------|
"""
        
        # Add Detection Rate data
        for service, rate in benchmark_report.service_comparison["detection_rate"].items():
            md_content += f"| {service} | {rate*100:.2f} |\n"
        
        # Add False Positive Rate section
        md_content += """
### False Positive Rate

| Service | False Positive Rate (%) |
|---------|------------------------|
"""
        
        # Add False Positive Rate data
        for service, rate in benchmark_report.service_comparison["false_positive_rate"].items():
            md_content += f"| {service} | {rate*100:.2f} |\n"
        
        # Add Scenario Results section
        md_content += """
## Scenario Results

"""
        
        # Add data for each scenario
        for scenario_id, scenario_data in benchmark_report.scenario_results.items():
            md_content += f"### Scenario: {scenario_id}\n\n"
            
            md_content += "| Service | MTTD (seconds) | Detection Rate (%) | False Positives |\n"
            md_content += "|---------|----------------|-------------------|----------------|\n"
            
            for service_name, service_data in scenario_data["services"].items():
                mttd = service_data["mttd"]
                mttd_str = f"{mttd:.2f}" if mttd >= 0 else "N/A"
                detection_rate = service_data["detection_rate"] * 100
                false_positives = service_data["false_positives"]
                
                md_content += f"| {service_name} | {mttd_str} | {detection_rate:.2f} | {false_positives} |\n"
            
            md_content += "\n"
        
        # Add Service Details section
        md_content += """
## Service Details

| Service | Type | Provider | Version |
|---------|------|----------|---------|
"""
        
        # Add Service Details data
        for service_name, details in benchmark_report.service_details.items():
            service_type = details.get("type", "unknown")
            provider = details.get("provider", "unknown")
            version = details.get("version", "unknown")
            
            md_content += f"| {service_name} | {service_type} | {provider} | {version} |\n"
        
        # Write Markdown file
        with open(md_path, 'w') as f:
            f.write(md_content)
            
        logger.info(f"Markdown report generated at {md_path}")
        
        return md_path