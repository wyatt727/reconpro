# reconpro/core/updater.py
import os
import logging
from pathlib import Path
from .config import (
    DATA_DIR, PAYLOADS_DIR, NUCLEI_TEMPLATES_DIR, GF_PATTERNS_DIR
)

logger = logging.getLogger(__name__)

def ensure_directory(path):
    """Ensure directory exists"""
    Path(path).mkdir(parents=True, exist_ok=True)

async def verify_resources() -> bool:
    """Verify that all required resources are present"""
    try:
        # Ensure directories exist
        for directory in [DATA_DIR, PAYLOADS_DIR, NUCLEI_TEMPLATES_DIR, GF_PATTERNS_DIR]:
            ensure_directory(directory)
            if not os.path.exists(directory):
                logger.error(f"Required directory {directory} is missing")
                return False
            
            # Check if directory is empty - just warn but don't fail
            if not os.listdir(directory):
                logger.warning(f"Directory {directory} is empty. Please ensure required files are installed.")

        logger.info("All required directories are present")
        return True

    except Exception as e:
        logger.error(f"Error verifying resources: {e}")
        return False

# For backwards compatibility
async def update_resources() -> None:
    """Verify resources are present"""
    if not await verify_resources():
        logger.warning("Some resources are missing. Please ensure all data files are properly installed.")
