import re
from typing import List, Dict, Any

# --- 1. Mock Vulnerability Database (Simulating a real CVE database) ---

# In a real SCA tool, this data would be fetched live from a service like the NVD or Snyk.
MOCK_VULNERABILITY_DB: List[Dict[str, Any]] = [
    {
        "package": "requests",
        "version_vulnerable_until": "2.26.0",
        "cve": "CVE-2021-3110",
        "severity": "HIGH",
        "description": "Potential credential leakage in HTTP header handling."
    },
    {
        "package": "flask",
        "version_vulnerable_until": "2.0.0",
        "cve": "CVE-2020-28177",
        "severity": "MEDIUM",
        "description": "Session fixation vulnerability."
    },
    {
        "package": "jinja2",
        "version_vulnerable_until": "3.0.0",
        "cve": "CVE-2020-35431",
        "severity": "CRITICAL",
        "description": "Remote Code Execution (RCE) via custom filters."
    },
    {
        "package": "numpy",
        "version_vulnerable_until": "1.23.0",
        "cve": "CVE-2022-3110",
        "severity": "LOW",
        "description": "Minor array indexing issue."
    },
]

# --- 2. Mock Dependency File (Simulating requirements.txt content) ---

# This simulates reading a project's dependency file
MOCK_REQUIREMENTS_CONTENT = """
# Project dependencies for Python SCA Demo

# Vulnerable dependencies
requests==2.25.1
jinja2==2.11.3

# Safe dependency
pandas==1.5.0
safe_package==1.0.0

# Another vulnerable dependency
flask==1.1.2

# A non-vulnerable version of a vulnerable package
numpy==1.25.0
"""

# --- 3. Core SCA Functions ---

def parse_dependencies(requirements_content: str) -> Dict[str, str]:
    """
    Parses a requirements file string and extracts package names and versions.
    Example: "package==1.2.3" -> {"package": "1.2.3"}
    """
    dependencies = {}
    
    # Regex to find package==version lines, ignoring comments/empty lines
    pattern = re.compile(r"^\s*([\w\-]+)\s*==\s*([\d\.]+)", re.MULTILINE)
    
    for match in pattern.finditer(requirements_content):
        package_name = match.group(1).lower()
        version = match.group(2)
        dependencies[package_name] = version
        
    return dependencies

def version_is_vulnerable(installed_version: str, vulnerable_until: str) -> bool:
    """
    Simple version comparison logic (major.minor.patch).
    Checks if installed_version < vulnerable_until.
    """
    try:
        # Convert versions to tuples of integers for easy comparison
        installed_parts = [int(p) for p in installed_version.split('.')]
        vulnerable_parts = [int(p) for p in vulnerable_until.split('.')]
        
        # Pad shorter version with 0s for comparison (e.g., '1.0' vs '1.0.5')
        max_len = max(len(installed_parts), len(vulnerable_parts))
        installed_parts += [0] * (max_len - len(installed_parts))
        vulnerable_parts += [0] * (max_len - len(vulnerable_parts))
        
        # Compare tuples lexicographically
        return installed_parts < vulnerable_parts

    except ValueError:
        # Handle non-standard version strings gracefully
        print(f"Warning: Could not compare versions {installed_version} and {vulnerable_until}. Assuming non-vulnerable.")
        return False


def scan_for_vulnerabilities(dependencies: Dict[str, str], db: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Scans the project dependencies against the vulnerability database.
    """
    vulnerability_report = []
    
    for package_name, installed_version in dependencies.items():
        
        for vuln_entry in db:
            if vuln_entry["package"].lower() == package_name:
                
                vulnerable_until = vuln_entry["version_vulnerable_until"]
                
                if version_is_vulnerable(installed_version, vulnerable_until):
                    # Found a match!
                    report_entry = {
                        "package": package_name,
                        "installed_version": installed_version,
                        "severity": vuln_entry["severity"],
                        "cve": vuln_entry["cve"],
                        "vulnerable_until": vulnerable_until,
                        "description": vuln_entry["description"]
                    }
                    vulnerability_report.append(report_entry)
                    
    return vulnerability_report

def generate_report(report: List[Dict[str, Any]], dependencies: Dict[str, str]):
    """
    Prints a nicely formatted SCA summary report.
    """
    print("==============================================")
    print("      SOFTWARE COMPOSITION ANALYSIS (SCA)")
    print("==============================================")
    print(f"Total dependencies scanned: {len(dependencies)}")
    print(f"Total vulnerabilities found: {len(report)}")
    print("----------------------------------------------")

    if not report:
        print("\n✅ Good news! No known vulnerabilities found in your current dependencies.")
        return

    # Sort report by severity (Critical > High > Medium > Low)
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_report = sorted(
        report, 
        key=lambda x: severity_order.get(x['severity'].upper(), 0), 
        reverse=True
    )

    for vuln in sorted_report:
        severity_color = {
            "CRITICAL": "\033[91m", # Red
            "HIGH": "\033[93m",     # Yellow
            "MEDIUM": "\033[94m",   # Blue
            "LOW": "\033[92m",      # Green
        }.get(vuln['severity'].upper(), "\033[0m") # Default: Reset
        
        reset_color = "\033[0m"

        print(f"\n{severity_color}❗ VULNERABILITY FOUND ({vuln['cve']}){reset_color}")
        print(f"  Package: {vuln['package']} (Installed: {vuln['installed_version']})")
        print(f"  Severity: {severity_color}{vuln['severity']}{reset_color}")
        print(f"  Fix Version: Upgrade to >= {vuln['vulnerable_until']}")
        print(f"  Description: {vuln['description']}")
        print("  --------------------------------")

# --- 4. Execution ---

if __name__ == "__main__":
    
    # 1. Parse Dependencies
    project_dependencies = parse_dependencies(MOCK_REQUIREMENTS_CONTENT)
    print("Parsed Dependencies:", project_dependencies)
    
    # 2. Run the SCA Scan
    vulnerabilities = scan_for_vulnerabilities(project_dependencies, MOCK_VULNERABILITY_DB)
    
    # 3. Generate the Final Report
    generate_report(vulnerabilities, project_dependencies)
