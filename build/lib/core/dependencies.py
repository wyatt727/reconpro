import shutil
import subprocess
import sys
import logging

# Define dependencies and their installation commands per platform.
DEPENDENCIES = {
    "gau": {
        "darwin": ["brew", "install", "gau"],
        "linux": ["sudo", "apt-get", "install", "-y", "gau"],
    },
    "subfinder": {
        "darwin": ["brew", "install", "subfinder"],
        "linux": ["sudo", "apt-get", "install", "-y", "subfinder"],
    },
    "waybackurls": {
        "darwin": lambda: install_waybackurls_with_go(),
        "linux": ["sudo", "apt-get", "install", "-y", "waybackurls"],
    },
}

def install_waybackurls_with_go():
    """Installs waybackurls using Go (for macOS)."""
    if not shutil.which("go"):
        logging.error("Go is not installed. Please install Go to automatically install waybackurls.")
        return None
    # The command returned here is used for installation.
    return ["go", "install", "github.com/tomnomnom/waybackurls@latest"]

def check_and_install_binary(binary, command_source):
    """Checks if the binary exists; if not, uses its command to install it."""
    if shutil.which(binary):
        logging.info("%s is already installed.", binary)
        return True
    else:
        logging.info("%s not found; attempting to install.", binary)
        # If a callable (lambda) is provided, call it to get the command.
        install_cmd = command_source() if callable(command_source) else command_source
        if not install_cmd:
            return False
        try:
            subprocess.run(install_cmd, check=True)
            logging.info("Successfully installed %s.", binary)
            return True
        except subprocess.CalledProcessError as e:
            logging.error("Failed to install %s: %s", binary, e)
            return False

def check_dependencies():
    """Loops through and checks all dependencies, installing those that are missing."""
    for binary, commands in DEPENDENCIES.items():
        if sys.platform == "darwin":
            command = commands.get("darwin")
        elif sys.platform.startswith("linux"):
            command = commands.get("linux")
        else:
            logging.error("Automatic installation for %s is not supported on this platform.", binary)
            continue
        check_and_install_binary(binary, command) 