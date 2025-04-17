#!/usr/bin/env python3
"""
Setup script for the MTTD Benchmarking Framework.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mttd-benchmarking",
    version="0.1.0",
    author="MTTD Benchmarking Team",
    author_email="example@example.com",
    description="A framework for benchmarking Mean Time to Detect across cloud security services",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/mttd-benchmarking",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=[
        "boto3>=1.26.0",
        "azure-identity>=1.12.0",
        "azure-mgmt-security>=3.0.0",
        "google-cloud-securitycenter>=1.16.0",
        "jsonschema>=4.16.0",
        "pyyaml>=6.0",
        "requests>=2.28.0",
        "python-dateutil>=2.8.2"
    ],
    entry_points={
        "console_scripts": [
            "mttd-benchmark=mttd_benchmarking.cli.cli:main",
        ],
    },
)