# setup.py
from setuptools import setup, find_packages

setup(
    name="reconpro",
    version="0.1.0",
    description="Full-Fledged Recon & Fuzzing Tool with Web Scraping, GF, and Nuclei Integration",
    author="Your Name",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "aiohttp",
        "requests",
        "beautifulsoup4",
        "tqdm"
    ],
    entry_points={
        "console_scripts": [
            "reconpro = reconpro.main:main"
        ]
    },
)
