"""
MTTD Benchmarking Framework

A standardized methodology for measuring and comparing Mean Time to Detect (MTTD)
across different commercial cloud security services.
"""

__version__ = "0.1.0"

from .core.types import (
    CloudProvider,
    ThreatScenario,
    SimulationResult,
    DetectionEvent,
    MetricsResult,
    BenchmarkReport
)

from .scenario.manager import ScenarioManager
from .scenario.validator import ScenarioValidator
from .simulation.engine import ThreatSimulationEngine
from .detection.monitor import DetectionMonitor
from .metrics.collector import MetricsCollector
from .metrics.analyzer import MetricsAnalyzer
from .reporting.generators import ReportGenerator, DetailedReportGenerator
from .core.utils import (
    setup_logging,
    load_config,
    save_config,
    format_duration
)

# Export main components
__all__ = [
    "CloudProvider",
    "ThreatScenario",
    "SimulationResult",
    "DetectionEvent",
    "MetricsResult",
    "BenchmarkReport",
    "ScenarioManager",
    "ScenarioValidator",
    "ThreatSimulationEngine",
    "DetectionMonitor",
    "MetricsCollector",
    "MetricsAnalyzer",
    "ReportGenerator",
    "DetailedReportGenerator",
    "setup_logging",
    "load_config",
    "save_config",
    "format_duration"
]