"""
Visualization generators for benchmark reports.
"""

import logging
import os
import uuid
import json
import base64
from io import BytesIO
from typing import Dict, List, Optional, Any, Union, Tuple

from ..core.types import BenchmarkReport, MetricsResult

logger = logging.getLogger(__name__)

# Check for optional dependencies
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import numpy as np
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False
    logger.warning("Matplotlib not available. Some visualizations will be limited.")


class VisualizationGenerator:
    """
    Generates visualization charts and graphs for benchmark reports.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the visualization generator.
        
        Args:
            config: Configuration options
        """
        self.config = config or {}
        self.output_dir = self.config.get("output_dir", "reports")
        self.chart_width = self.config.get("chart_width", 10)
        self.chart_height = self.config.get("chart_height", 6)
        self.chart_dpi = self.config.get("chart_dpi", 100)
        self.color_scheme = self.config.get("color_scheme", [
            "#4e79a7", "#f28e2c", "#e15759", "#76b7b2", "#59a14f",
            "#edc949", "#af7aa1", "#ff9da7", "#9c755f", "#bab0ab"
        ])
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def generate_mttd_chart(self, benchmark_report: BenchmarkReport) -> Optional[str]:
        """
        Generate a bar chart comparing MTTD across services.
        
        Args:
            benchmark_report: The benchmark report to visualize
            
        Returns:
            Path to the generated chart file or None if visualization not available
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Cannot generate MTTD chart: matplotlib not available")
            return None
            
        mttd_data = benchmark_report.service_comparison.get("mttd", {})
        if not mttd_data:
            logger.warning("No MTTD data available for visualization")
            return None
            
        # Filter out invalid values
        valid_data = {
            service: mttd for service, mttd in mttd_data.items() 
            if mttd is not None and mttd >= 0
        }
            
        if not valid_data:
            logger.warning("No valid MTTD data available for visualization")
            return None
        
        # Create figure
        plt.figure(figsize=(self.chart_width, self.chart_height), dpi=self.chart_dpi)
        
        # Sort services by MTTD for better visualization
        sorted_services = sorted(valid_data.items(), key=lambda x: x[1])
        services = [item[0] for item in sorted_services]
        mttds = [item[1] for item in sorted_services]
        
        # Create bar chart
        bars = plt.bar(services, mttds, color=self.color_scheme[:len(services)])
        
        # Add labels and title
        plt.xlabel('Service')
        plt.ylabel('Mean Time To Detect (seconds)')
        plt.title('MTTD Comparison Across Services')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.2f}s',
                     ha='center', va='bottom', rotation=0)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save chart
        chart_path = os.path.join(self.output_dir, f"mttd_chart_{benchmark_report.report_id}.png")
        plt.savefig(chart_path)
        plt.close()
        
        logger.info(f"Generated MTTD chart: {chart_path}")
        return chart_path
    
    def generate_detection_rate_chart(self, benchmark_report: BenchmarkReport) -> Optional[str]:
        """
        Generate a bar chart comparing detection rates across services.
        
        Args:
            benchmark_report: The benchmark report to visualize
            
        Returns:
            Path to the generated chart file or None if visualization not available
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Cannot generate detection rate chart: matplotlib not available")
            return None
            
        detection_data = benchmark_report.service_comparison.get("detection_rate", {})
        if not detection_data:
            logger.warning("No detection rate data available for visualization")
            return None
        
        # Create figure
        plt.figure(figsize=(self.chart_width, self.chart_height), dpi=self.chart_dpi)
        
        # Sort services by detection rate for better visualization
        sorted_services = sorted(detection_data.items(), key=lambda x: x[1], reverse=True)
        services = [item[0] for item in sorted_services]
        rates = [item[1] * 100 for item in sorted_services]  # Convert to percentage
        
        # Create bar chart
        bars = plt.bar(services, rates, color=self.color_scheme[:len(services)])
        
        # Add labels and title
        plt.xlabel('Service')
        plt.ylabel('Detection Rate (%)')
        plt.title('Detection Rate Comparison Across Services')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.1f}%',
                     ha='center', va='bottom', rotation=0)
        
        # Set y-axis limit to 100%
        plt.ylim(0, 110)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save chart
        chart_path = os.path.join(self.output_dir, f"detection_rate_chart_{benchmark_report.report_id}.png")
        plt.savefig(chart_path)
        plt.close()
        
        logger.info(f"Generated detection rate chart: {chart_path}")
        return chart_path
    
    def generate_false_positive_chart(self, benchmark_report: BenchmarkReport) -> Optional[str]:
        """
        Generate a bar chart comparing false positive rates across services.
        
        Args:
            benchmark_report: The benchmark report to visualize
            
        Returns:
            Path to the generated chart file or None if visualization not available
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Cannot generate false positive chart: matplotlib not available")
            return None
            
        fp_data = benchmark_report.service_comparison.get("false_positive_rate", {})
        if not fp_data:
            logger.warning("No false positive rate data available for visualization")
            return None
        
        # Create figure
        plt.figure(figsize=(self.chart_width, self.chart_height), dpi=self.chart_dpi)
        
        # Sort services by false positive rate for better visualization
        sorted_services = sorted(fp_data.items(), key=lambda x: x[1])
        services = [item[0] for item in sorted_services]
        rates = [item[1] * 100 for item in sorted_services]  # Convert to percentage
        
        # Create bar chart
        bars = plt.bar(services, rates, color=self.color_scheme[:len(services)])
        
        # Add labels and title
        plt.xlabel('Service')
        plt.ylabel('False Positive Rate (%)')
        plt.title('False Positive Rate Comparison Across Services')
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                     f'{height:.1f}%',
                     ha='center', va='bottom', rotation=0)
        
        # Adjust layout
        plt.tight_layout()
        
        # Save chart
        chart_path = os.path.join(self.output_dir, f"false_positive_chart_{benchmark_report.report_id}.png")
        plt.savefig(chart_path)
        plt.close()
        
        logger.info(f"Generated false positive chart: {chart_path}")
        return chart_path
    
    def generate_radar_chart(self, benchmark_report: BenchmarkReport) -> Optional[str]:
        """
        Generate a radar chart comparing services across multiple metrics.
        
        Args:
            benchmark_report: The benchmark report to visualize
            
        Returns:
            Path to the generated chart file or None if visualization not available
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Cannot generate radar chart: matplotlib not available")
            return None
            
        # Get data for each metric
        mttd_data = benchmark_report.service_comparison.get("mttd", {})
        detection_data = benchmark_report.service_comparison.get("detection_rate", {})
        fp_data = benchmark_report.service_comparison.get("false_positive_rate", {})
        
        # Get common services across all metrics
        services = set(mttd_data.keys()) & set(detection_data.keys()) & set(fp_data.keys())
        
        if not services:
            logger.warning("No common services across all metrics for radar chart")
            return None
        
        # Create figure
        plt.figure(figsize=(self.chart_width, self.chart_height), dpi=self.chart_dpi)
        
        # Number of variables (metrics)
        N = 3
        
        # What will be the angle of each axis in the plot
        angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
        
        # Make the plot circular
        angles += angles[:1]
        
        # Set up subplot with polar projection
        ax = plt.subplot(111, polar=True)
        
        # Set the labels for each axis
        labels = ['Detection Rate', 'Inverse MTTD', 'Inverse FP Rate']
        plt.xticks(angles[:-1], labels)
        
        # Draw y-axis labels
        ax.set_rlabel_position(0)
        plt.yticks([0.2, 0.4, 0.6, 0.8, 1.0], ["0.2", "0.4", "0.6", "0.8", "1.0"])
        plt.ylim(0, 1)
        
        # Plot each service
        for i, service in enumerate(services):
            # Get values for each metric, normalize to [0,1] range
            
            # Detection rate (already in [0,1])
            dr_value = detection_data.get(service, 0)
            
            # MTTD: Lower is better, so invert and normalize
            # Assume max reasonable MTTD is 1 hour (3600s)
            if service in mttd_data and mttd_data[service] >= 0:
                mttd_value = max(0, 1 - (mttd_data[service] / 3600))
            else:
                mttd_value = 0
            
            # FP Rate: Lower is better, so invert
            fp_value = 1 - fp_data.get(service, 0)
            
            # Create data array
            values = [dr_value, mttd_value, fp_value]
            
            # Make it circular
            values += values[:1]
            
            # Get color from scheme
            color = self.color_scheme[i % len(self.color_scheme)]
            
            # Plot the service on the radar chart
            ax.plot(angles, values, linewidth=2, linestyle='solid', label=service, color=color)
            ax.fill(angles, values, alpha=0.1, color=color)
        
        # Add legend
        plt.legend(loc='upper right', bbox_to_anchor=(0.1, 0.1))
        
        # Add title
        plt.title('Service Comparison Across All Metrics')
        
        # Save radar chart
        chart_path = os.path.join(self.output_dir, f"radar_chart_{benchmark_report.report_id}.png")
        plt.savefig(chart_path)
        plt.close()
        
        logger.info(f"Generated radar chart: {chart_path}")
        return chart_path
    
    def generate_timeline_chart(self, metrics_results: List[MetricsResult]) -> Optional[str]:
        """
        Generate a timeline chart showing detection times.
        
        Args:
            metrics_results: List of metrics results
            
        Returns:
            Path to the generated chart file or None if visualization not available
        """
        if not MATPLOTLIB_AVAILABLE:
            logger.warning("Cannot generate timeline chart: matplotlib not available")
            return None
            
        if not metrics_results:
            logger.warning("No metrics results available for timeline chart")
            return None
        
        # Create figure
        plt.figure(figsize=(self.chart_width, self.chart_height), dpi=self.chart_dpi)
        
        # Group results by service name
        service_results = {}
        for result in metrics_results:
            if result.service_name not in service_results:
                service_results[result.service_name] = []
            service_results[result.service_name].append(result)
        
        # Set up plot
        plt.xlabel('Scenario')
        plt.ylabel('Mean Time To Detect (seconds)')
        plt.title('MTTD by Scenario and Service')
        
        # Create data points for the chart
        service_names = list(service_results.keys())
        
        # Group results by scenario
        scenarios = set()
        for results in service_results.values():
            scenarios.update(result.scenario_id for result in results)
        
        scenarios = sorted(scenarios)
        
        # Position bars for each scenario
        x = np.arange(len(scenarios))
        width = 0.8 / len(service_names)  # Width of bars, adjusted for number of services
        
        # Plot bars for each service
        for i, service_name in enumerate(service_names):
            results = service_results[service_name]
            
            # Get MTTD for each scenario
            mttds = []
            for scenario in scenarios:
                # Find MTTD for this scenario and service
                scenario_results = [r.mttd for r in results if r.scenario_id == scenario and r.mttd >= 0]
                if scenario_results:
                    mttd = sum(scenario_results) / len(scenario_results)
                else:
                    mttd = float('nan')  # Use NaN for missing data
                
                mttds.append(mttd)
            
            # Plot bars for this service
            positions = x - 0.4 + (i + 0.5) * width
            color = self.color_scheme[i % len(self.color_scheme)]
            bars = plt.bar(positions, mttds, width, label=service_name, color=color)
            
            # Add value labels on bars
            for j, bar in enumerate(bars):
                height = bar.get_height()
                if not np.isnan(height):
                    plt.text(bar.get_x() + bar.get_width()/2., height,
                             f'{height:.1f}',
                             ha='center', va='bottom', rotation=90, fontsize=8)
        
        # Set x-axis labels
        plt.xticks(x, scenarios, rotation=45, ha='right')
        
        # Add legend
        plt.legend()
        
        # Adjust layout
        plt.tight_layout()
        
        # Generate a unique ID for this chart
        chart_id = uuid.uuid4()
        
        # Save chart
        chart_path = os.path.join(self.output_dir, f"timeline_chart_{chart_id}.png")
        plt.savefig(chart_path)
        plt.close()
        
        logger.info(f"Generated timeline chart: {chart_path}")
        return chart_path
    
    def generate_all_charts(self, benchmark_report: BenchmarkReport, metrics_results: List[MetricsResult] = None) -> Dict[str, str]:
        """
        Generate all available charts for a benchmark report.
        
        Args:
            benchmark_report: The benchmark report to visualize
            metrics_results: Optional list of detailed metrics results
            
        Returns:
            Dictionary mapping chart types to file paths
        """
        charts = {}
        
        # Generate basic charts
        mttd_chart = self.generate_mttd_chart(benchmark_report)
        if mttd_chart:
            charts["mttd"] = mttd_chart
            
        detection_chart = self.generate_detection_rate_chart(benchmark_report)
        if detection_chart:
            charts["detection_rate"] = detection_chart
            
        fp_chart = self.generate_false_positive_chart(benchmark_report)
        if fp_chart:
            charts["false_positive"] = fp_chart
            
        radar_chart = self.generate_radar_chart(benchmark_report)
        if radar_chart:
            charts["radar"] = radar_chart
        
        # Generate timeline chart if metrics results provided
        if metrics_results:
            timeline_chart = self.generate_timeline_chart(metrics_results)
            if timeline_chart:
                charts["timeline"] = timeline_chart
                
        return charts
    
    def chart_to_base64(self, chart_path: str) -> Optional[str]:
        """
        Convert a chart image to base64 for embedding in HTML.
        
        Args:
            chart_path: Path to the chart image
            
        Returns:
            Base64-encoded image data or None if file not found
        """
        if not os.path.exists(chart_path):
            logger.warning(f"Chart file not found: {chart_path}")
            return None
            
        try:
            with open(chart_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                return encoded_string
        except Exception as e:
            logger.error(f"Failed to encode chart as base64: {str(e)}")
            return None
    
    def generate_html_chart_library(self) -> str:
        """
        Generate an HTML file with JavaScript functions for interactive charts.
        
        Returns:
            Path to the generated HTML library file
        """
        # Create a basic Chart.js library for use in HTML reports
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>MTTD Benchmarking Chart Library</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>MTTD Benchmarking Chart Library</h1>
    <p>This file contains JavaScript functions for generating interactive charts.</p>
    
    <script>
        /**
         * Create a bar chart comparing MTTD across services.
         * @param {string} canvasId - ID of the canvas element
         * @param {Object} data - Chart data with services and MTTD values
         */
        function createMTTDChart(canvasId, data) {
            const ctx = document.getElementById(canvasId).getContext('2d');
            
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: data.services,
                    datasets: [{
                        label: 'Mean Time To Detect (seconds)',
                        data: data.values,
                        backgroundColor: ['#4e79a7', '#f28e2c', '#e15759', '#76b7b2', '#59a14f',
                                         '#edc949', '#af7aa1', '#ff9da7', '#9c755f', '#bab0ab'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'MTTD Comparison Across Services'
                        },
                        legend: {
                            display: false
                        }
                    },
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
        }
        
        /**
         * Create a radar chart comparing services across multiple metrics.
         * @param {string} canvasId - ID of the canvas element
         * @param {Object} data - Chart data with services and metrics
         */
        function createRadarChart(canvasId, data) {
            const ctx = document.getElementById(canvasId).getContext('2d');
            
            new Chart(ctx, {
                type: 'radar',
                data: {
                    labels: ['Detection Rate', 'Inverse MTTD', 'Inverse FP Rate'],
                    datasets: data.datasets
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Service Comparison Across All Metrics'
                        }
                    },
                    scales: {
                        r: {
                            beginAtZero: true,
                            max: 1
                        }
                    }
                }
            });
        }
    </script>
</body>
</html>
"""
        
        # Save to file
        library_path = os.path.join(self.output_dir, "chart_library.html")
        with open(library_path, "w") as f:
            f.write(html_content)
            
        logger.info(f"Generated HTML chart library: {library_path}")
        return library_path