# reconpro/config.py
SCAN_INTERVAL = 300          # seconds between scan cycles
CONCURRENCY = 10             # HTTP request concurrency
SIMILARITY_THRESHOLD = 0.95  # response similarity threshold for vulnerability detection
TIMEOUT = 15                 # timeout for HTTP requests (in seconds)

# Paths for local resources:
DATA_DIR = "data"
PAYLOADS_DIR = f"{DATA_DIR}/payloads"
NUCLEI_TEMPLATES_DIR = f"{DATA_DIR}/nuclei_templates"
GF_PATTERNS_DIR = f"{DATA_DIR}/gf_patterns"

# GitHub API endpoints:
PAYLOADS_REPO_API = "https://api.github.com/repos/coffinxp/payloads/contents"
NUCLEI_TEMPLATES_REPO_API = "https://api.github.com/repos/coffinxp/nuclei-templates/contents"
GF_PATTERNS_REPO_API = "https://api.github.com/repos/coffinxp/GFpattren/contents"
