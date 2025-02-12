# reconpro/core/updater.py
import os
import requests
import logging
from config import DATA_DIR, PAYLOADS_DIR, NUCLEI_TEMPLATES_DIR, GF_PATTERNS_DIR, PAYLOADS_REPO_API, NUCLEI_TEMPLATES_REPO_API, GF_PATTERNS_REPO_API

def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def download_files_from_repo(api_url, extension, dest_dir):
    ensure_directory(dest_dir)
    try:
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()
        items = response.json()
        for item in items:
            if item.get("type") == "file" and item.get("name", "").lower().endswith(extension):
                file_name = item.get("name")
                dest_file = os.path.join(dest_dir, file_name)
                if os.path.exists(dest_file):
                    logging.info("File %s already exists in %s, skipping download.", file_name, dest_dir)
                    continue
                file_url = item.get("download_url")
                file_response = requests.get(file_url, timeout=10)
                file_response.raise_for_status()
                with open(dest_file, "w", encoding="utf-8") as f:
                    f.write(file_response.text)
                logging.info("Downloaded %s to %s", file_name, dest_dir)
    except Exception as e:
        logging.error("Error downloading files from %s: %s", api_url, e)

def update_resources():
    logging.info("Updating resources from GitHub...")
    download_files_from_repo(PAYLOADS_REPO_API, ".txt", PAYLOADS_DIR)
    download_files_from_repo(NUCLEI_TEMPLATES_REPO_API, ".yaml", NUCLEI_TEMPLATES_DIR)
    download_files_from_repo(GF_PATTERNS_REPO_API, ".json", GF_PATTERNS_DIR)
    logging.info("Resource update complete.")
