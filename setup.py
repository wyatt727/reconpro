# setup.py
from setuptools import setup, find_packages
from setuptools.command.install import install
import subprocess
import os
import sys

class CustomInstall(install):
    """Custom handler for installing Go tools."""
    def run(self):
        # First run the standard installation
        install.run(self)
        
        # Install Go if not already installed
        try:
            subprocess.check_call(['go', 'version'])
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("Go is not installed. Please install Go from https://golang.org/")
            sys.exit(1)

        # List of Go tools to install
        go_tools = [
            "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/katana/cmd/katana@latest",
            "github.com/tomnomnom/gf@latest",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/tomnomnom/waybackurls@latest",
            "github.com/hakluke/hakrawler@latest",
            "github.com/lc/gau@latest",
            "github.com/ffuf/ffuf@latest",
            "github.com/hahwul/dalfox/v2@latest",
            "github.com/jaeles-project/jaeles@latest",
            "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
            "github.com/KathanP19/Gxss@latest",
            "github.com/hahwul/meg@latest",
            "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
            "github.com/d3mondev/puredns/v2@latest",
            "github.com/owasp-amass/amass/v4/...@latest",
            "github.com/aboul3la/Sublist3r@latest",
            "github.com/ticarpi/jwt_tool@latest"
        ]

        print("Installing Go tools...")
        for tool in go_tools:
            try:
                print(f"Installing {tool}...")
                subprocess.check_call(['go', 'install', tool])
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to install {tool}: {e}")

        # Install additional tools using system package manager if available
        if sys.platform.startswith('linux'):
            try:
                # For Debian/Ubuntu based systems
                subprocess.check_call(['sudo', 'apt-get', 'update'])
                subprocess.check_call(['sudo', 'apt-get', 'install', '-y',
                    'nmap',
                    'wappalyzer',
                    'graphviz',
                    'jq'
                ])
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to install system packages: {e}")
        elif sys.platform == 'darwin':
            try:
                # For macOS using Homebrew
                subprocess.check_call(['brew', 'install',
                    'nmap',
                    'wappalyzer',
                    'graphviz',
                    'jq'
                ])
            except subprocess.CalledProcessError as e:
                print(f"Warning: Failed to install Homebrew packages: {e}")

        # Create necessary directories
        dirs = [
            'data/payloads',
            'data/nuclei-templates',
            'data/gf-patterns',
            'reports'
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)

        print("Installation completed successfully!")

setup(
    name="reconpro",
    version="1.0.0",
    description="Advanced Web Security Scanner with Real-time Monitoring",
    author="ReconPro Team",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "aiohttp[speedups]>=3.8.0",
        "fastapi>=0.68.0",
        "uvicorn[standard]>=0.15.0",
        "jinja2>=3.0.0",
        "python-multipart>=0.0.5",
        "websockets>=10.0",
        "aiosqlite>=0.17.0",
        "beautifulsoup4>=4.9.3",
        "httpx[http2]>=0.23.0",
        "pydantic>=1.8.0",
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "python-dotenv>=0.19.0",
        "aiofiles>=0.8.0",
        "tqdm>=4.62.0",
        "certifi>=2024.2.0",
        "yarl>=1.9.0",
        "charset-normalizer>=3.0.0",
        "aiodns>=3.0.0",
        "brotli>=1.0.9",
        "ujson>=5.7.0",
        "cryptography>=41.0.0",
        "pyOpenSSL>=23.2.0",
        "urllib3[secure]>=2.0.0",
        "requests[security]>=2.31.0",
        "certvalidator>=0.11.1",
        "jwt>=1.3.1",
        "pyjwt>=2.8.0"
    ],
    extras_require={
        "dev": [
            "pytest>=6.2.5",
            "pytest-asyncio>=0.16.0",
            "pytest-cov>=2.12.1",
            "black>=21.7b0",
            "isort>=5.9.3",
            "mypy>=0.910",
            "flake8>=3.9.2",
        ]
    },
    entry_points={
        "console_scripts": [
            "reconpro=main:main"
        ]
    },
    cmdclass={
        'install': CustomInstall,
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: FastAPI",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
    project_urls={
        "Documentation": "https://github.com/yourusername/reconpro/wiki",
        "Source": "https://github.com/yourusername/reconpro",
        "Tracker": "https://github.com/yourusername/reconpro/issues",
    },
)
