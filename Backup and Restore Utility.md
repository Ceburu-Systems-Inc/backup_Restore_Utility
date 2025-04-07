# Backup and Restore Utility for Network Devices - Documentation

## Overview

The Backup and Restore Utility for Network Devices is a command-line tool designed to automate the backup and restoration of network device configurations. This utility functions as an agent initiated by our existing management system and provides the following capabilities:

- Secure SSH connections to network devices
- Automatic vendor, model, and OS version detection
- Configuration backup creation and management
- Multiple storage options (local, AWS S3, backend server)
- Configuration restoration from backup files
- Comprehensive logging and reporting

## Architecture

### Backup Process Flow

1. **Connection Establishment**: Creates a secure SSH connection to the target device
2. **Device Identification**: Determines vendor, model, and OS by analyzing command outputs
3. **Configuration Extraction**: Executes vendor-specific commands to generate a backup
4. **Secure Transfer**: Retrieves the backup file from the device using SCP
5. **Storage Management**: Uploads the backup to the configured storage destination
6. **Cleanup Operations**: Removes temporary files from the network device

### Restore Process Flow

1. **Backup Acquisition**: Retrieves the specified backup file (local or remote)
2. **Device Transfer**: Securely copies the configuration file to the target device
3. **Configuration Application**: Executes vendor-specific commands to apply the configuration
4. **Validation**: Performs integrity checks to confirm successful restoration

## Storage Options

The utility supports two primary storage configurations:

- **Ceburu Network**: Securely stores backups in an AWS S3 bucket with versioning support
- **Own Network**: Transmits backup files to a specified backend server where they are stored in a media directory for comparison and archival purposes

## Command-Line Interface

```bash
./Backup_Restore_Utility.exe \
  --id <command-id>                # Unique identifier for the backup operation
  --devicename <device-name>       # Friendly name of the target device
  --routerip <ip-address>          # IP address of the target device
  --username <username>            # SSH authentication username
  --password <password>            # SSH authentication password
  --backup_type <storage-option>   # "Ceburu Network" or "Own Network"
  --restore_file_path <path>       # Path/URL to restore file (or "None" for backup)
  --aws_bucket_name <bucket-name>  # AWS S3 bucket name (if applicable)
  --aws_access_key <access-key>    # AWS access credentials (if applicable)
  --aws_secret_key <secret-key>    # AWS secret credentials (if applicable)
  --api_url <url>                  # Backend API endpoint for reporting
  --token <api-token>              # API authentication token
```

## Integration Workflow

1. A command is generated based on user configuration and stored in the remote command table
2. When the agent processes the command, it initiates this utility
3. The utility executes the requested operation (backup or restore)
4. Operation logs and backup files (if applicable) are transmitted to the configured backend URL
5. The system records the operation status and updates the command state


This utility is designed as a modular component that can eventually replace the existing backup/restore functionality. The development roadmap includes:

- Support for additional network device vendors and models
- Enhanced security features and credential management
- Improved error handling and automatic retry mechanisms
- Potential integration into the main agent codebase


## Installation and Path Configuration

The utility path needs to be properly configured in command while genrating based on where we place it in installation directory.

**Note:** For development and testing purposes, the executable path is currently hardcoded in commands. Before production deployment, this must be modified to use the actual installation directory path based on your environment configuration.

The utility is being developed as a standalone tool initially to avoid disrupting existing backup and restore functionality. Once validated in production environments, we will determine whether to maintain it as a separate component or integrate it with the primary agent.