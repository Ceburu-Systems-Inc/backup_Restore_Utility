import paramiko
import time
import os
from datetime import datetime
import requests
from scp import SCPClient
import logging
import argparse
import boto3

 
def connect_ssh_shell(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=22, username=username, password=password, look_for_keys=False, allow_agent=False)
    print(f"SSH connection established to {host}...")
    return ssh.invoke_shell()
 
def connect_ssh(host, username, password):
    ssh = paramiko.SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=22, username=username, password=password, look_for_keys=False, allow_agent=False)
    print(f"SSH connection established to {host}...")
    return ssh
 
def detect_vendor(shell):
    # Try detecting the vendor using specific commands
    commands = {
        "cisco": ("show version\n", ["cisco", "ios", "nx-os"]),
        "juniper": ("show version\n", ["junos"]),
        "huawei": ("display version\n", ["vrp", "huawei"]),
        "arista": ("show version\n", ["arista"]),
        "brocade": ("show version\n", ["brocade"]),
        "fortinet": ("get system status\n", ["fortinet"]),
        "palo_alto": ("show system info\n", ["palo alto"]),
        "h3c": ("display version\n", ["h3c"]),
        "dell": ("show version\n", ["dell"]),
        "mikrotik": ("/system resource print\n", ["routeros"]),
        "netgear": ("show version\n", ["netgear"]),
        "linksys": ("show version\n", ["linksys"]),
        "ubiquiti": ("show version\n", ["ubiquiti"]),
        "zyxel": ("show version\n", ["zyxel"]),
        "aruba": ("show version\n", ["aruba"]),
        "cumulus": ("show version\n", ["cumulus"]),
        "edgecore": ("show version\n", ["edgecore"]),
        "extreme": ("show version\n", ["extreme"]),
    }

    logging.info("Detecting vendor...")
    for vendor, (command, keywords) in commands.items():
        shell.send(command)
        logging.info(f"Running command: {command.strip()}")
        time.sleep(3)
        output = shell.recv(65535).decode("utf-8").lower()
        logging.info(f"Received output for {vendor}: {output}")
        if any(keyword in output for keyword in keywords):
            return vendor
    return "Unknown"
 
def detect_device_details(shell, vendor):
    logging.info(f"Detecting device details for vendor: {vendor}")
    commands = {
        "cisco": "show version\n",
        "juniper": "show chassis hardware\n",
        "huawei": "display version\n",
        "arista": "show version\n",
        "brocade": "show version\n",
        "fortinet": "get system status\n",
        "palo_alto": "show system info\n",
        "h3c": "display version\n",
        "dell": "show version\n",
        "mikrotik": "/system resource print\n",
        "netgear": "show version\n",
        "linksys": "show version\n",
        "ubiquiti": "show version\n",
        "zyxel": "show version\n",
        "aruba": "show version\n",
        "cumulus": "show version\n",
        "edgecore": "show version\n",
        "extreme": "show version\n",
    }

    if vendor not in commands:
        raise ValueError(f"Unsupported vendor: {vendor}")
    
    logging.info(f"Running command to detect device details: {commands[vendor].strip()}")
    shell.send(commands[vendor])
    time.sleep(3)
    output = shell.recv(65535).decode("utf-8").lower()
    logging.info(f"Received output for device details: {output}")
    model, os_version = "Unknown", "Unknown"
    
    for line in output.splitlines():
        if vendor == "cisco":
            if "model number" in line or ("cisco" in line and "model" in line):
                model = line.split(":")[-1].strip()
            elif "cisco ios software" in line or "ios-xe" in line:
                os_version = line.strip()
            elif "nx-os" in line:
                os_version = "NX-OS"
            elif "adaptive security appliance" in line:
                os_version = "ASA"
            elif "ios xr" in line:
                os_version = "IOS-XR"
        elif vendor == "juniper":
            if "model:" in line:
                model = line.split(":")[-1].strip()
            elif "junos" in line:
                os_version = line.strip()
        elif vendor == "huawei":
            if "device model" in line or "vrp" in line:
                model = line.split(":")[-1].strip()
            elif "version" in line and "vrp" in line:
                os_version = line.strip()

    return model, os_version
 
 
def get_backup_command(vendor, os_version, model):
    logging.info(f"Getting backup command for vendor: {vendor}, OS version: {os_version}, model: {model}")

    if vendor == "cisco":
        if "asa" in os_version.lower():
            return "copy running-config flash:/backup_new.cfg\n"
        return "copy running-config flash:/backup_new.cfg\n"
        # https://community.cisco.com/t5/switching/saving-my-config-file-on-flash-or-nvram-and-using-it-when/td-p/2094879
    
    elif vendor == "juniper":
        return "save /var/tmp/backup.cfg\n"
        # https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/save.html
    
    elif vendor == "huawei":
        return "save flash:/backup.cfg\n"
        # https://support.huawei.com/enterprise/en/doc/EDOC1000178166/4adec9f7/saving-the-configuration-file
    return None
 
 
def detect_and_backup_conf_to_flash(device):
    ip = device['ip']
    username = device['username']
    password = device['password']
    logging.info(f"Connecting to {ip}...")
    vendor = None  # Initialize outside try block
    
    try:
        shell = connect_ssh_shell(ip, username, password)
        print(f"Connected to {ip}...")
        logging.info(f"Connected to {ip}...")
        time.sleep(1)
        shell.recv(1000)
        shell.send("terminal length 0\n")
        logging.info(f"Setting terminal length to 0...")
        shell.send("screen-length 0 temporary\n")
        logging.info(f"Setting screen length to 0 temporary...")
        shell.send("set cli screen-length 0\n")
        logging.info(f"Setting CLI screen length to 0...")
        time.sleep(1)
        shell.recv(1000)
        logging.info(f"Detecting vendor...")
        vendor = detect_vendor(shell)
        logging.info(f"Detected vendor: {vendor}")
        model, os_version = detect_device_details(shell, vendor)
        print(f"Detected vendor: {vendor}, model: {model}, OS version: {os_version}")
        logging.info(f"Detected vendor: {vendor}, model: {model}, OS version: {os_version}")    
        command = get_backup_command(vendor, os_version, model)
        if not command:
            logging.error(f"Unsupported vendor: {vendor}")
            raise Exception(f"Unsupported vendor: {vendor}")
            
        logging.info(f"Running command to create backup: {command.strip()}")
       # Create backup file on the device
        if vendor == "cisco":
            shell.send(f"copy running-config flash:backup_new.cfg\n\n")
        elif vendor == "juniper":
            shell.send("show configuration | save backup_new.cfg\n")
        elif vendor == "huawei":
            shell.send("save flash:/backup.cfg\n")
            shell.send("Y\n")
        else:
            raise Exception(f"Unsupported vendor: {vendor}")
        time.sleep(3)
        shell.recv(65535)
        logging.info(f"Backup file created on device: {vendor}")
        print(f"Backup file created on device: {vendor}")
 
        return vendor  # Return here on success
 
    except Exception as e:
        logging.error(f"Error during backup: {str(e)}")
        return None  # Optionally return None on failure
 
    finally:
        try:
            shell.close()
            logging.info(f"Closed SSH connection to {ip}")
        except:
            logging.error(f"Failed to close SSH connection to {ip}")
            pass
 
       
def backup_to_remote(device, output_dir, vendor, local_backup_file):
    logging.info("Backing up to remote...")
    ip = device['ip']
    username = device['username']
    password = device['password']
    logging.info(f"Connecting to {ip}...")

    try:       
        if vendor == "cisco":
            remote_file = "backup_new.cfg"
        elif vendor == "juniper":
            remote_file = "backup_new.cfg"
        elif vendor == "huawei":
            remote_file = "backup.cfg"
        else:
            logging.error(f"Unsupported vendor for SCP: {vendor}")
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        
        outfile = os.path.join(output_dir, local_backup_file)  # Local file path to save the backup 
        logging.info(f"Remote file to copy: {remote_file}")
        print(f"Remote file to copy: {remote_file}")
        logging.info(f"Preparing to copy backup file from device to local directory: {outfile}")

        # Use SCP to copy the file from the device
        if vendor != "huawei":
            ssh = connect_ssh(ip, username, password)
            print(f"Connected to {ip}...")
            scp = SCPClient(ssh.get_transport(), socket_timeout=100)
            logging.info(f"SCP session created for {ip}...")
            print(f"Copying backup file from device to local directory...")
            logging.info(f"Copying backup file from device to local directory...")
            scp.get(remote_file)
            logging.info(f"Backup file copied to local directory: {outfile}")
            os.rename(remote_file, outfile)
            print(f"Backup file copied to {outfile}")
            logging.info(f"Backup file copied to {outfile}")
            time.sleep(5)
            # Close the SCP session
            scp.close()
            ssh.close()
            print(f"SSH connection closed for {ip}")
            logging.info(f"SSH connection closed for {ip}")

        # For Huawei devices, we need to handle the backup differently since SCP might not work as expected
        # Instead, we will use SSH to read the file and save it locally
        else:
            shell = connect_ssh_shell(ip, username, password)
            print(f"Connected to {ip}... over ssh")
            logging.info('Connected to huawei over ssh')
            time.sleep(1)
            shell.recv(1000)
            shell.send("terminal length 0\n")
            time.sleep(1)  # Give some time for the command to execute
            shell.send("screen-length 0 temporary\n")
            time.sleep(1)  # Give some time for the command to execute
            shell.send("set cli screen-length 0\n")
            time.sleep(1)
            logging.info(f"Preparing to copy backup file from Huawei device to local directory: {outfile}")
            time.sleep(1)
            shell.recv(1000)
            command = f"more {remote_file}\n"
            shell.send(command)
            time.sleep(3)  # Give some time for the command to execute and output to be generated
            # Capture the output from the shell
            stdout = shell.recv(65535).decode("utf-8").splitlines()  # Capture the output of the command
            # ignoring line 1 from stdout
            if len(stdout) > 0:
                stdout = stdout[1:-1]  # Ignore the first line which is usually a prompt or header
            logging.info(f"Executing command on Huawei device: {command}")
            time.sleep(3)
            # Capture output and save locally
            with open(outfile, "w") as f:
                for line in stdout:
                    f.write(line + "\n")
            logging.info(f"Backup file saved locally: {outfile}")
            shell.close()
            logging.info(f"Closed shell connection for {device['ip']}")
            logging.info(f"Backup process completed for {device['ip']}")


    except Exception as e:
        logging.error(f"Error during SCP transfer: {str(e)}")
    finally:
        try:
            scp.close()
            logging.info(f"SCP session closed for {ip}")
            time.sleep(2)
            ssh.close()
        except:
            logging.error(f"Failed to close SCP session for {ip}")
            pass
       
def clean_up(device, vendor):
    ip = device['ip']
    username = device['username']
    password = device['password']

    try:
        shell = connect_ssh_shell(ip, username, password)
        print(f"Connected to {ip}...")
        time.sleep(1)
        shell.recv(1000)
        shell.send("terminal length 0\n")
        shell.send("screen-length 0 temporary\n")
        shell.send("set cli screen-length 0\n")
        time.sleep(1)
        shell.recv(1000)
        # Clean up the file on the device
        if vendor == "cisco":
            shell.send("delete backup_new.cfg\n\n")
            time.sleep(1)
            shell.send("\n")  # Accept default filename
            time.sleep(1)
            shell.send("\n")  # Confirm delete
        elif vendor == "juniper":
            shell.send("file delete /var/tmp/backup.cfg\n")
        elif vendor == "huawei":
            shell.send("delete backup.cfg\nY\n")
        print(f"Temporary backup file deleted from device.")
        time.sleep(2)
        shell.recv(65535)

    except Exception as e:
        logging.error(f"Error during cleanup: {str(e)}")

    finally:
        try:
            shell.close()
            time.sleep(2)
            print(f"closed cleaup shell.")
            logging.info(f"closed cleanup shell.")
        except:
            pass
       
def perform_backup(device, output_dir, local_backup_file):
    logging.info("Performing backup...")
    vendor = detect_and_backup_conf_to_flash(device)
    if vendor is not None:
        logging.info(f"Vendor detected: {vendor}")
        time.sleep(5)
        backup_to_remote(device, output_dir, vendor, local_backup_file)
        logging.info(f"Backup completed for vendor: {vendor}")
        time.sleep(5)
        clean_up(device, vendor)  # Uncommenting the clean_up function call
        time.sleep(5)
    else:
        logging.error("Failed to execute backup: Vendor is None")
        print("Failed to execute backup: Vendor is  None")
   
       
def perform_restore(device):
    ip = device['ip']
    username = device['username']
    password = device['password']
    config_file = device['restore_file_path']
    
    try:
        # Step 1: Detect the vendor using SSH
        print(f"Connecting to {ip} to detect vendor...")
        logging.info(f"Connecting to {ip} to detect vendor...")
        shell = connect_ssh_shell(ip, username, password)
        vendor = detect_vendor(shell)
        shell.close()
        time.sleep(5)
        print(f"Detected vendor: {vendor}")
        logging.info(f"Detected vendor: {vendor}")
        logging.info(f"Restoring configuration for device {ip}...")
        # Step 2: Use SCP to copy the restore file to the device
        print(f"Copying restore file to {ip}...")
        logging.info(f"Copying restore file to {ip}...")
        
        if vendor == "cisco":
            remote_file = "restore.cfg"
        elif vendor == "juniper":
            remote_file = "restore.cfg"
        elif vendor == "huawei":
            remote_file = "flash:/restore.cfg"
        else:
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        
        logging.info(f"Remote file to copy: {remote_file}")
        print(f"Uploading {config_file} to {remote_file} on {ip}...")
        logging.info(f"Uploading {config_file} to {remote_file} on {ip}...")
        scp = None
         
 

        try:
            # For non-Huawei devices, use SCP to upload the file
            if vendor != 'huawei':
                ssh = connect_ssh(ip, username, password)
                # Increase SCP timeout and add progress callback
                def progress(filename, size, sent):
                    print(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")
                    logging.info(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred") 

                logging.info(f"Creating SCP session for {ip}...")
                scp = SCPClient(ssh.get_transport(), socket_timeout=100, progress=progress)
                logging.info(f"SCP session created for {ip}...")
                scp.put(config_file, remote_file)
                print(f"File successfully uploaded to {ip}")
                logging.info(f"File successfully uploaded to {ip}")
            
            # For Huawei devices, use SSH to upload the configuration file
            else:
                shell = connect_ssh_shell(ip, username, password)
                time.sleep(5)
                logging.info(f"Connected to Huawei device for SCP upload...")

                with open(config_file, "r") as f:
                    config_lines = f.readlines()

                shell.recv(1000)
                shell.send("system-view\n")
                shell.recv(1000)
                logging.info(f"Entering system-view mode on Huawei device...")

                for line in config_lines:
                    shell.send(line.strip() + "\n")
                    shell.recv(500)

                logging.info(f"Sending configuration lines to Huawei device...")
                time.sleep(2)
                shell.send("commit\n")  # Commit the changes in Huawei's system-view mode
                shell.recv(1000)
                # Save the config
                logging.info(f"Saving configuration on Huawei device...")
                shell.send("save\n")
                shell.recv(2000)
                shell.send("Y\n")  # Confirm the save prompt
                shell.recv(2000)
                
                # Close the shell
                logging.info(f"Closing SSH connection to Huawei device...")
                shell.close()
                ssh.close()

        except Exception as e:
            print(f"Error during SCP upload to {ip}: {str(e)}")
            logging.error(f"Error during SCP upload to {ip}: {str(e)}")
            raise
        finally:
            if scp:
                try:
                    scp.close()
                    print(f"SCP session closed for {ip}")
                    logging.info(f"SCP session closed for {ip}")
                except Exception as e:
                    print(f"Failed to close SCP session for {ip}: {str(e)}")
                    logging.error(f"Failed to close SCP session for {ip}: {str(e)}")
        ssh.close()
        print(f"Restore file copied to {ip}")
        logging.info(f"Restore file copied to {ip}")
        time.sleep(5)
        # Step 3: Use SSH to apply the restore configuration
        print(f"Applying restore configuration on {ip}...")
        logging.info(f"Applying restore configuration on {ip}...")
        shell = connect_ssh_shell(ip, username, password)
        if vendor == "cisco":
            print(f"Restoring configuration on Cisco device...")
            logging.info(f"Restoring configuration on Cisco device...")
            shell.send("copy restore.cfg running-config\n")
            logging.info(f"Copying restore.cfg to running-config...")
            time.sleep(2)
            shell.send("\n")  # Accept default filename
            time.sleep(1)
            shell.send("copy running-config startup-config\n")
            logging.info(f"Copying running-config to startup-config...")
            time.sleep(1)
            shell.send("\n")  # Accept default filename
            time.sleep(1)
        elif vendor == "juniper":
            print(f"Restoring configuration on Juniper device...")
            logging.info(f"Restoring configuration on Juniper device...")
            shell.send("configure exclusive\n")
            logging.info(f"Entering exclusive configuration mode...")
            time.sleep(1)
            shell.send("load override /var/tmp/restore  .cfg\n")
            logging.info(f"Loading configuration from restore.cfg...")
            time.sleep(1)
            shell.send("commit and-quit\n")
            logging.info(f"Committing configuration and quitting...")
            time.sleep(1)
 
        print(f"Restore configuration applied on {ip}")
        logging.info(f"Restore configuration applied on {ip}")
        
 
    except Exception as e:
        print(f"Restore failed on {ip}: {str(e)}")
        logging.error(f"Restore failed on {ip}: {str(e)}")
    finally:
        try:
            shell.close()
            print(f"Closed SSH connection to {ip}")
            logging.info(f"Closed SSH connection to {ip}")
        except Exception as e:
            print(f"Failed to close SSH connection to {ip}")
            logging.error(f"Failed to close SSH connection to {ip}, {str(e)}")
 
  
 
def main():
    # Setting up logging to file with timestamp
    temp_output_dir = os.path.join(os.getcwd(), 'temp_output_backup_restore')
    os.makedirs(temp_output_dir, exist_ok=True)
    log_file_path = os.path.join(temp_output_dir,f'script_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    logging.info("Starting Network Device Configuration Manager - Backup and Restore Tool")
    # command = f"{id} {routerip} {username} {password} {devicename} {backup_type} {restore_file_path} {aws_bucket_name} {aws_access_key} {aws_secret_key} {token} {api_url}"
 
    parser = argparse.ArgumentParser(description="Network Device Configuration Manager - Backup and Restore Tool. Sample usage: ./Backup_Restore_Switches_Routers_Utility_Agent.exe <id> <ip> <username> <password> <type> <restore_file_path> <aws_bucket_name> <aws_access_key> <aws_secret_key> <api_url> <api_key>")
    parser.add_argument("id", help="Backup command ID")
    parser.add_argument("devicename", help="Device name")
    parser.add_argument("routerip", help="Device IP address")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("password", help="SSH password")
    parser.add_argument("backup_type", help="Backup Type - Ceburu Network / Own Network")
    parser.add_argument("restore_file_path", help="Path / url to the restore file")  # Updated to match argument name
    parser.add_argument("aws_bucket_name", help="AWS bucket name")  # Updated to match argument name
    parser.add_argument("aws_access_key", help="AWS access key")  # Updated to match argument name
    parser.add_argument("aws_secret_key", help="AWS secret key")  # Updated to match argument name
    parser.add_argument("api_url", help="API URL for backend server to send backup file and log file")  # Added API URL argument for backend server
    parser.add_argument("token", help="API key for backend server")  # Added API key argument for backend server

    # Parse the command line arguments
    args = parser.parse_args()
    backup_command_id = args.id
    ip = args.routerip
    device_name = args.devicename
    username = args.username
    password = args.password
    backup_type = args.backup_type
    restore_file_path = args.restore_file_path
    aws_bucket_name = args.aws_bucket_name
    aws_access_key = args.aws_access_key
    aws_secret_key = args.aws_secret_key
    api_url = args.api_url  # Backend server API URL
    api_key = args.token  # Backend server API key
    

    logging.info("Starting backup/restore operation for device: {}".format(device_name))
    logging.info(f"Backup command ID: {backup_command_id}")
    logging.info(f"Device IP: {ip}")
    logging.info(f"Username: {username}")
    logging.info(f"Backup Type: {backup_type}")
    logging.info(f"Restore file path: {restore_file_path}")
    logging.info(f"AWS bucket name: {aws_bucket_name}")
    logging.info(f"using  temorary output directory: {temp_output_dir}")

    local_backup_file = f'{backup_command_id}_{device_name}.cfg' # Default backup file name based on backup_command_id and device_name
    logging.info("Starting backup / restore operation...")
    print("Starting backup / restore operation...")
    local_restore_file = None

    # Check if restore_file_path is provided for restore operation
    if restore_file_path:
        logging.info(f"Restore file path provided: {restore_file_path}")
        logging.info(f"Performing restore operation...")

        # downloading the restore file from the provided path if it's a URL
        if restore_file_path.startswith("http://") or restore_file_path.startswith("https://"):
            response = requests.get(restore_file_path)
            if response.status_code == 200:
                local_restore_file = os.path.join(temp_output_dir, os.path.basename(local_backup_file))
                with open(local_restore_file, 'wb') as f:
                    f.write(response.content)
                logging.info(f"Restore file downloaded to: {local_restore_file}")
            else:
                logging.error(f"Failed to download restore file: {response.status_code}")
                print(f"Failed to download restore file: {response.status_code}")
                return

        device = {
            'ip': ip,
            'username': username,
            'password': password,
            'restore_file_path': local_restore_file  # Pass the local restore file path to the device dictionary
        }
        perform_restore(device)
        logging.info(f"Restore completed for device {ip}")
        print(f"Restore completed for device {ip}")

    else:
        device = {
            'ip': ip,
            'username': username,
            'password': password
        }
        perform_backup(device, temp_output_dir, local_backup_file)
        logging.info(f"Backup completed for device {ip}")
        print(f"Backup completed for device {ip}")   
 
   # closing log file
    logging.info("Closing log file...")
    print("Closing log file...")

    for handler in logging.getLogger().handlers:
        handler.close()
        logging.getLogger().removeHandler(handler)

    if not restore_file_path:
        if backup_type.lower() == "ceburu network":
            print(f"Uploading backup file to AWS S3 bucket {aws_bucket_name}...")
            s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
            s3.upload_file(local_backup_file, aws_bucket_name, os.path.basename(local_backup_file))
            print(f"Backup file uploaded to AWS S3 bucket {aws_bucket_name}")
            print(f"Uploading log file to AWS S3 bucket {aws_bucket_name}...")
            s3.upload_file(log_file_path, aws_bucket_name, os.path.basename(log_file_path))
            print(f"Log file uploaded to AWS S3 bucket {aws_bucket_name}")

        elif backup_type.lower() == "own network":
            # sending backup and log file to backend server
            files = {'file': open(local_backup_file, 'rb'), 'log': open(log_file_path, 'rb')}
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Authorization': "Token " + api_key}
            response = requests.post(api_url, files=files, data={'backup_command_id': backup_command_id, }, headers=headers)
            if response.status_code == 200:
                print(f"Backup file and log file uploaded to backend server")
            else:
                print(f"Failed to upload files to backend server: {response.status_code}")


    # deleting local backup and log files
    if os.path.exists(local_backup_file):
        os.remove(local_backup_file)
        print(f"Local backup file {local_backup_file} deleted")

    # deleting local log file if it exists
    if os.path.exists(log_file_path):
        os.remove(log_file_path)
        print(f"Local log file {log_file_path} deleted")

    # deleting local restore file if it exists and was downloaded
    if local_restore_file and os.path.exists(local_restore_file):
        os.remove(local_restore_file)
        print(f"Local restore file {local_restore_file} deleted")

    # deleting temp directory
    if os.path.exists(temp_output_dir):
        os.rmdir(temp_output_dir)
        print(f"Temp directory {temp_output_dir} deleted")

if __name__ == "__main__":
    main()