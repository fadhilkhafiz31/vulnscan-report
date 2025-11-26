import ipaddress
import re
import shutil

def check_nmap_installed() -> bool:
    """
    Checks if Nmap is installed and available in the system PATH.
    """
    return shutil.which("nmap") is not None

def validate_target(target: str) -> bool:
    """
    Validates if the target is a valid IP address or hostname.
    
    Args:
        target: The target string to validate.
        
    Returns:
        True if valid, False otherwise.
    """
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
        
    # If it looks like an IP (only digits and dots), but failed ip_address check, it's invalid
    if all(c.isdigit() or c == '.' for c in target):
        return False

    # Check if it's a valid hostname
    # Regex for hostname validation (simplified)
    # Allowed: alphanumeric, hyphens, dots. Max length 253.
    if len(target) > 255:
        return False
        
    if target[-1] == ".":
        target = target[:-1] # strip exactly one dot from the right, if present
        
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in target.split("."))
