from pathlib import Path
from setuptools import setup, find_packages

setup(
    name="threatkb",
    version="2.0.0",
    description="Detection engineering and threat intelligence workbench",
    python_requires=">=3.14",
    packages=find_packages(exclude=["tests", "build", "dist", "env"]),
    install_requires=[line for line in Path("requirements.in").read_text().splitlines()
                      if line and not line.startswith("#")],
    include_package_data=True,
    license="GPL-2.0",
)
