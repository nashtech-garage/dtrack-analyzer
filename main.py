import os
import csv
from enum import Enum
from typing import List, Dict
import itertools
import requests

from dotenv import load_dotenv
load_dotenv()

# Dependency-Track API information details
DTRACK_URL = os.environ.get("DTRACK_URL")
API_KEY = os.environ.get("API_KEY")
REPORT_FILE_NAME = os.environ.get("REPORT_FILE_NAME", "dependency_track_report.csv")
HEADERS = {"X-Api-Key": API_KEY, "Content-Type": "application/json"}
PAGE_SIZE = 100  # Number of items per API request
REQUEST_TIMEOUT = 60  # 60 seconds


# Severity levels
class Severity(Enum):
    """Severity levels"""
    UNASSIGNED = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


# Data classes for better organization
class Vulnerability:
    """ Vulnerability class"""
    def __init__(self):
        self.vuln_id = ""
        self.severity = ""
        

class Component:
    """Component class"""
    def __init__(self):
        self.name = ""
        self.version = ""
        self.latest_version = "N/A"
        self.license = "N/A"
        self.risk_score = 0.0
        self.vulnerabilities: List[Vulnerability] = []
        self.severity_summary = ""


# Helper function to fetch all pages of data
def fetch_all(url: str) -> List[Dict]:
    """Fetches all pages of data from the given API endpoint."""
    items: List[Dict] = []
    offset = 0
    while True:
        try:
            response = requests.get(
                    f"{url}?offset={offset}&limit={PAGE_SIZE}",
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT
                )
            response.raise_for_status()  # Raise an exception for bad status codes
            data = response.json()
            if not data:  # Stop when no more results
                break
            items.extend(data)
            offset += PAGE_SIZE  # Move to the next page
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data from {url}: {e}")
            break
    return items


# Fetch all projects
def get_projects() -> List[Dict]:
    """Fetches all projects from Dependency-Track."""
    return fetch_all(f"{DTRACK_URL}/project")


# Fetch components for a given project
def get_components(project_uuid: str) -> List[Dict]:
    """Fetches all components for a specific project."""
    return fetch_all(f"{DTRACK_URL}/component/project/{project_uuid}")


# Fetch vulnerabilities for a given component
def get_vulnerabilities(component_uuid: str) -> List[Dict]:
    """Fetches all vulnerabilities for a specific component."""
    return fetch_all(f"{DTRACK_URL}/vulnerability/component/{component_uuid}")


# Extract required fields and write to CSV
def generate_csv():
    """Fetches data, processes it, and generates the CSV report."""
    projects = get_projects()
    unique_components = {}
    unique_component_vulnerabilities = {}

    print("Fetching and processing components...")
    components: List[Component] = []
    for project in projects:
        project_uuid = project["uuid"]
        if not project_uuid:
            print(f"Warning: Project missing UUID. Skipping project: {project.get('name', 'N/A')}")
            continue
        returned_components = get_components(project_uuid)

        for returned_component in returned_components:
            # Skip components where classifier is "APPLICATION"
            if returned_component.get("classifier") == "APPLICATION":
                continue

            component = Component()
            component.name = returned_component.get("name", "N/A")
            component.version = returned_component.get("version", "N/A")

            # Extract latest version
            component.latest_version = returned_component.get("repositoryMeta", {}).get("latestVersion", "N/A")

            # Extract license name
            component.license = returned_component.get("license") or returned_component.get("resolvedLicense", {}).get("name", "N/A")

            # Extract risk score
            component.risk_score = returned_component.get("lastInheritedRiskScore", 0)

            # Get severity_summary
            if component.risk_score > 0:
                if ((component.name, component.version) not in unique_component_vulnerabilities):
                    returned_vulnerabilities = get_vulnerabilities(returned_component.get("uuid"))
                    for returned_vulnerability in returned_vulnerabilities:
                        vulnerability = Vulnerability()
                        vulnerability.vuln_id = returned_vulnerability.get("vulnId")
                        vulnerability.severity = Severity[returned_vulnerability.get("severity")]
                        component.vulnerabilities.append(vulnerability)
                    unique_component_vulnerabilities[(component.name, component.version)] = component.vulnerabilities
                else:
                    component.vulnerabilities = unique_component_vulnerabilities[(component.name, component.version)]

                severities = {}
                for vulnerability in component.vulnerabilities:
                    if vulnerability.severity.name not in severities.keys():
                        severities[vulnerability.severity.name] = []
                    severities[vulnerability.severity.name].append(vulnerability.vuln_id)

                for key, value in severities.items():
                    component.severity_summary = component.severity_summary + f'{key}: {", ".join(value)} | '
                component.severity_summary = component.severity_summary[:-3]

            # Use (name, version) as a unique key to avoid duplicates
            unique_components[(component.name, component.version)] = component

    # Sort components by package name
    components = sorted(unique_components.values(), key=lambda x: x.name)

    # Generate the summary table
    print("Generating summary table...")
    summary_table = []
    i = 0
    while i < len(components):
        if components[i].risk_score > 0:
            summary_row = {}
            summary_row["name"] = components[i].name
            summary_row["version"] = {components[i].version}
            summary_row["lastest_version"] = components[i].latest_version
            summary_row["license"] = {components[i].license}
            summary_row["risk_score"] = components[i].risk_score
            j = i + 1
            while j < len(components):
                if components[i].name == components[j].name:
                    summary_row["version"].add(components[j].version)
                    summary_row["license"].add(components[j].license)
                    if components[j].risk_score > summary_row["risk_score"]:
                        summary_row["risk_score"] = components[j].risk_score
                    i += 1
                    j += 1
                else:
                    break
            summary_table.append(summary_row)
        i += 1

    summary_table_csv = []
    summary_table.sort(key=lambda x: x["risk_score"], reverse=True)
    for row in summary_table:
        recommendation = ""
        if row["risk_score"] >= 10:
            recommendation = "'First Priority' due to high risk score"
        elif row["risk_score"] == 8:
            recommendation = "'Second Priority'"
        else:
            recommendation = "'Third Priority'"
        summary_table_csv.append([row["name"],
                                  "\r\n".join(list(row["version"])),
                                  row["lastest_version"],
                                  "\r\n".join(list(row["license"])),
                                  f"- Risk type: Security risk\r\n\r\n"
                                  f"- Security risk score: {row['risk_score']} "
                                  f"(taken from the version having the highest risk score). "
                                  f"See Details sheet for the full list of security risks.\r\n\r\n"
                                  f"- Recommendation: Upgrade the component ({recommendation})"])

    # Generate executive summary
    print("Generating executive summary...")
    components_with_risk = [component for component in components if component.risk_score > 0]
    high_risk_components = [
        vulnerabilities
        for component in components_with_risk
        if (vulnerabilities := [
            vulnerability
            for vulnerability in component.vulnerabilities
            if vulnerability.severity in [Severity.CRITICAL, Severity.HIGH, Severity.UNASSIGNED]
        ])
        and len(vulnerabilities) > 0
    ]

    low_risk_components = [
        vulnerabilities
        for component in components_with_risk
        if (vulnerabilities := [
            vulnerability
            for vulnerability in component.vulnerabilities
            if vulnerability.severity not in [Severity.CRITICAL, Severity.HIGH, Severity.UNASSIGNED]
        ])
        and len(vulnerabilities) > 0
    ]

    high_risk_cve = set([x.vuln_id for x in list(itertools.chain(*high_risk_components))])
    low_risk_cve = set([x.vuln_id for x in list(itertools.chain(*low_risk_components))])

    executive_summary = (
        f"The scan has identified a total of {len(high_risk_cve) + len(low_risk_cve)} CVEs. "
        f"We recommend prioritizing the remediation of {len(high_risk_cve)} CVEs immediately due to their high risk. "
        f"The remaining {len(low_risk_cve)} CVEs can be addressed at a later time as they pose a lower risk. "
        F"For a comprehensive overview, please refer to the table below, which provides detailed information about each package and its associated CVEs."
    )
    # Write to CSV
    print(f"Writing data to CSV file: {REPORT_FILE_NAME}")
    components.sort(key=lambda x: x.risk_score, reverse=True)
    with open(REPORT_FILE_NAME, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([executive_summary])
        writer.writerow(["Summary"])
        writer.writerow(["Name", "Version", "Latest Version", "License", "Note"])
        writer.writerows(summary_table_csv)
        writer.writerow([""])
        writer.writerow([""])
        writer.writerow(["Name", "Version", "Latest Version", "License", "Risk Score", "Severity Summary"])
        writer.writerows((component.name, component.version, component.latest_version, component.license, component.risk_score, component.severity_summary) for component in components)

    print(f"CSV file generated: {REPORT_FILE_NAME}")


# Run script
if __name__ == "__main__":
    if not DTRACK_URL or not API_KEY:
        print("Error: DTRACK_URL and API_KEY environment variables must be set.")
    else:
        generate_csv()
