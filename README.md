# PowerShell List Weak Secrets Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for scanning files for weak or plain-text secrets (such as passwords, API keys, or tokens) across configurable directories.

---

## Overview

The `List-WeakSecrets.ps1` script recursively scans a specified directory for files likely to contain secrets (e.g., `.env`, `.ini`, `.txt`, `.json`), flags files containing keywords like `password`, `apikey`, `secret`, or `token`, and logs all actions, results, and errors in both a script log and an active-response log. It supports excluding system directories and limiting file size for scanning. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies files with weak/plain-text secrets
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\List-WeakSecrets.ps1 [-RootDir <string>] [-ExcludeSystem] [-MaxSizeMB <int>] [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter        | Type    | Default Value                                                    | Description                                  |
|------------------|---------|------------------------------------------------------------------|----------------------------------------------|
| `RootDir`        | string  | `C:\`                                                            | Root directory to scan                       |
| `ExcludeSystem`  | switch  | (off)                                                            | Exclude system folders from scan             |
| `MaxSizeMB`      | int     | `50`                                                             | Maximum file size (MB) to scan               |
| `LogPath`        | string  | `$env:TEMP\List-WeakSecrets.log`                                 | Path for execution logs                      |
| `ARLog`          | string  | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\List-WeakSecrets.ps1

# Scan a specific directory, exclude system folders, and set max file size
.\List-WeakSecrets.ps1 -RootDir "D:\Projects" -ExcludeSystem -MaxSizeMB 10

# Custom log path
.\List-WeakSecrets.ps1 -LogPath "C:\Logs\WeakSecrets.log"

# Integration with OSSEC/Wazuh active response
.\List-WeakSecrets.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Level` (string): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'
- `Message` (string): The log message

**Features**:
- Timestamped output
- File logging

**Usage**:
```powershell
Write-Log INFO "Scanned $($dirs.Count) dirs, $($files.Count) files. Flagged $($flagged.Count). JSON appended."
Write-Log ERROR "Failed to complete secret inventory: $_"
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

### `Log-FlaggedJSON`
**Purpose**: Appends structured JSON results to the active response log.

**Parameters**:
- `Data`: The flagged files array
- `DirCount`: Number of directories scanned
- `FileCount`: Number of files scanned

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation

2. **Execution**
   - Recursively scans for files matching patterns (`*.env`, `*.ini`, `*.txt`, `*.json`)
   - Optionally excludes system directories
   - Limits files by size
   - Flags files containing keywords: `password`, `apikey`, `secret`, `token`
   - Computes SHA256 hash for flagged files
   - Logs findings

3. **Completion**
   - Outputs flagged files as JSON to the active response log (with scan counts and hashes)
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details to the log

---

## JSON Output Format

### Flagged Files Example

```json
{
  "timestamp": "2025-07-22T10:30:45.123Z",
  "hostname": "HOSTNAME",
  "type": "weak_secrets_flagged",
  "scanned_directories": 120,
  "scanned_files": 350,
  "flagged": [
    {
      "FilePath": "D:\\Projects\\.env",
      "SizeKB": 2.13,
      "Match": "password\\s*=",
      "SHA256": "A1B2C3D4..."
    }
  ]
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the file/keyword patterns as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **File Access Issues**: Some files may be locked or inaccessible.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation and incident response purposes.
