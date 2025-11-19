import subprocess
import tempfile

def run_scan(target: str, profile: str = "default") -> str:
    """
    Runs an Nmap scan against the target and returns the path to the XML output file.
    
    Args:
        target: Target IP address or hostname
        profile: Scan profile - "default", "fast", "full", "top100", or "udp"
    
    Returns:
        Path to the generated XML output file
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    xml_path = tmp.name
    tmp.close()

    # Define scan profiles and their corresponding Nmap flags
    profile_flags = {
        "default": ["-sV", "-T4"],
        "fast": ["-F"],
        "full": ["-sV", "-T4", "-p-"],
        "top100": ["--top-ports", "100"],
        "udp": ["-sU"],
    }

    # Get flags for the selected profile
    flags = profile_flags.get(profile, profile_flags["default"])
    
    # Build the command
    cmd = ["nmap", "-oX", xml_path] + flags + [target]

    print(f"[*] Using scan profile: {profile}")
    print(f"[+] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    return xml_path
