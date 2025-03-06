# PowerShell Universal

## Overview
This directory contains public scripts, configurations, and documentation for PowerShell Universal provided by SYNTHETIXMIND LTD. PowerShell Universal is a platform for building web-based PowerShell tools and automation solutions with a modern, responsive web interface.

## Contents

- **Scripts**: Ready-to-use PowerShell scripts optimized for PowerShell Universal
- **Dashboards**: Pre-configured dashboard templates
- **API Examples**: Samples for integrating with PowerShell Universal's REST API
- **Configuration Settings**: Recommended configuration templates
- **Documentation**: Guides and best practices

## Getting Started

### Prerequisites
- PowerShell Universal (version 2.0 or higher)
- PowerShell 7.0+ (recommended)
- .NET 6.0+ runtime

### Installation

1. Clone this repository:
```powershell
git clone https://github.com/SYNTHETIXMIND/pubrepo.git
```

2. Copy the desired scripts to your PowerShell Universal scripts directory:
```powershell
Copy-Item -Path ".\pubrepo\PowerShell Universal\Scripts\*" -Destination "C:\ProgramData\PowerShellUniversal\Scripts\" -Recurse
```

3. Import configuration files as needed:
```powershell
Import-PSUConfiguration -Path ".\pubrepo\PowerShell Universal\Configurations\example-config.ps1"
```

## Usage Examples

### Running Scripts
```powershell
# Through the PowerShell Universal web interface
# Navigate to Scripts > [Script Name] > Run

# Via the PowerShell Universal API
Invoke-RestMethod -Uri "http://your-psu-server/api/v1/scripts/run/[script-id]" -Method POST -Headers @{Authorization = "Bearer $token"}
```

### Implementing Dashboards
```powershell
# Import dashboard template
Import-PSUDashboard -Path ".\pubrepo\PowerShell Universal\Dashboards\monitoring-dashboard.ps1"
```

## Best Practices

- Always test scripts in a non-production environment first
- Use PowerShell Universal roles and permissions to restrict access to sensitive scripts
- Consider implementing script signing for production environments
- Schedule resource-intensive scripts during off-peak hours

## Documentation

Detailed documentation for each component can be found in the `/Documentation` subdirectory. This includes:

- Script descriptions and parameter details
- Dashboard component explanations
- Configuration recommendations
- Performance optimization tips
- Security best practices

## Integration Examples

Examples for integrating PowerShell Universal with:
- Active Directory
- Azure
- AWS
- Git repositories
- CI/CD pipelines
- Monitoring systems

## Intellectual Property Notice
All scripts, configurations, and documentation are the exclusive intellectual property of SYNTHETIXMIND LTD. Usage is permitted according to the terms outlined in the main repository README.

## Disclaimer
These scripts and configurations are provided as-is, without warranty of any kind. Use at your own risk.

## Support
Support for the use of these PowerShell Universal resources is available on a fee basis only:

- **Email**: support@synthetixmind.com
- **Web**: https://support.synthetixmind.com

---

© 2025 SYNTHETIXMIND LTD. All rights reserved.