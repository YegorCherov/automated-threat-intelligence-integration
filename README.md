# Automated Threat Intelligence Integration

This PowerShell script provides an automated solution for integrating threat intelligence from multiple sources and checking the local system for potential threats. It retrieves the latest threat data from reputable providers, such as VirusTotal, OTX, and ThreatCrowd, and performs mitigation actions when matches are found on the local system.

## Features

- Retrieves the latest threat intelligence from VirusTotal, OTX, and ThreatCrowd APIs.
- Compares the retrieved threat data against the running processes and files on the local system.
- Performs mitigation actions, such as stopping processes and deleting files, when threats are detected.
- Runs in a continuous loop, checking for new threats at a configurable interval (default is 5 minutes).
- Demonstrates advanced PowerShell skills, including modular design, API integration, and automated threat mitigation.

## Usage

1. Clone the repository:
```
git clone https://github.com/Rozcy/automated-threat-intelligence-integration.git
```
2. Open the PowerShell script file (`Invoke-ThreatIntelligenceIntegration.ps1`) and update the API keys for VirusTotal, OTX, and any other threat intelligence providers you'd like to use.
3. Run the script:
```powershell
.\Invoke-ThreatIntelligenceIntegration.ps1
```
4. The script will continuously monitor the system for threats, retrieving the latest intelligence and performing mitigation actions as needed.

## Contributing

Contributions to this project are welcome. If you have any ideas, bug fixes, or feature enhancements, please feel free to submit a pull request.

## License

This project is licensed under the MIT License.
