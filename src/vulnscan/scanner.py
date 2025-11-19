import subprocess
import tempfile

def run_scan(target: str) -> str:
    """
    Runs an Nmap scan against the target and returns the path to the XML output file.
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    xml_path = tmp.name
    tmp.close()

    cmd = [
        "nmap",
        "-sV",          # service/version detection
        "-T4",          # faster timing
        "-oX", xml_path,
        target,
    ]

    print(f"[+] Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    return xml_path
