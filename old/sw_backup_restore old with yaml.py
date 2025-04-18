import paramiko
import time
import os
import yaml
from datetime import datetime
from scp import SCPClient
import logging

# Configure logging
logging.basicConfig(
    filename=os.path.join(os.getcwd(), 'script.log'),  # Log file in the current running location
    level=logging.INFO,  # Set the logging level
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)
 
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
 
 
def detect_copy(device, root_dir):
    ip = device['ip']
    username = device['username']
    password = device['password']
    logging.info(f"Connecting to {ip}...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
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
            shell.send("save /var/tmp/backup.cfg\n")
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
 
       
def backup_to_remote(device, root_dir, vendor):
    ip = device['ip']
    username = device['username']
    password = device['password']
   
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logging.info(f"Connecting to {ip}...")
    try:
        ssh = connect_ssh(ip, username, password)
        print(f"Connected to {ip}...")
       
    #     # Use SCP to copy the file from the device
        scp = SCPClient(ssh.get_transport(), socket_timeout=100)
        logging.info(f"SCP session created for {ip}...")
        print(f"Copying backup file from device to local directory...")
        logging.info(f"Copying backup file from device to local directory...")
        vendor_dir = os.path.join(root_dir, vendor)
        os.makedirs(vendor_dir, exist_ok=True)
        local_file = os.path.join(vendor_dir, f"{ip}_{vendor}_{timestamp}.cfg")
 
        if vendor == "cisco":
            remote_file = "backup_new.cfg"
        elif vendor == "juniper":
            remote_file = "/var/tmp/backup_new.cfg"
        elif vendor == "huawei":
            remote_file = "backup.cfg"
        else:
            logging.error(f"Unsupported vendor for SCP: {vendor}")
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        logging.info(f"Remote file to copy: {remote_file}")
        print(f"Remote file to copy: {remote_file}")
        scp.get(remote_file)
        logging.info(f"Backup file copied to local directory: {local_file}")
        os.rename("backup_new.cfg", local_file)
        print(f"Backup file copied to {local_file}")
        logging.info(f"Backup file copied to {local_file}")
        time.sleep(5)
        # Close the SCP session
        scp.close()
        ssh.close()
        print(f"SSH connection closed for {ip}")
        logging.info(f"SSH connection closed for {ip}")
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
       
def clean_up(device, root_dir, vendor):
    ip = device['ip']
    username = device['username']
    password = device['password']
   
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
 
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
            shell.send("delete flash:/backup.cfg\nY\n")
        print(f"Temporary backup file deleted from device.")
        time.sleep(2)
        #shell.recv(65535)
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
       
def perform_backup(device, root_dir):
    logging.info("Performing backup...")
    vendor = detect_copy(device, root_dir)
    if vendor is not None:
        logging.info(f"Vendor detected: {vendor}")
        time.sleep(5)
        backup_to_remote(device, root_dir, vendor)
        logging.info(f"Backup completed for vendor: {vendor}")
        time.sleep(5)
        # clean_up(device, root_dir, log, vendor)
        # time.sleep(5)
    else:
        logging.error("Failed to execute backup: Vendor is None")
        print("Failed to execute backup: Vendor is  None")
   
       
def perform_restore(device, root_dir):
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
        ssh = connect_ssh(ip, username, password)
        # ssh.get_transport().set_keepalive(30)  # Enable keepalive for legacy protocol support
 
        # Increase SCP timeout and add progress callback
        def progress(filename, size, sent):
            print(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")
            logging.info(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")  
 
        if vendor == "cisco":
            remote_file = "restore.cfg"
        elif vendor == "juniper":
            remote_file = "/var/tmp/restore.cfg"
        elif vendor == "huawei":
            remote_file = "flash:/restore.cfg"
        else:
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        logging.info(f"Remote file to copy: {remote_file}")
        print(f"Uploading {config_file} to {remote_file} on {ip}...")
        logging.info(f"Uploading {config_file} to {remote_file} on {ip}...")
        scp = None
        try:
            logging.info(f"Creating SCP session for {ip}...")
            scp = SCPClient(ssh.get_transport(), socket_timeout=100, progress=progress)
            logging.info(f"SCP session created for {ip}...")
            scp.put(config_file, remote_file)
            print(f"File successfully uploaded to {ip}")
            logging.info(f"File successfully uploaded to {ip}")
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
            shell.send("load override /var/tmp/restore.cfg\n")
            logging.info(f"Loading configuration from restore.cfg...")
            time.sleep(1)
            shell.send("commit and-quit\n")
            logging.info(f"Committing configuration and quitting...")
            time.sleep(1)
        elif vendor == "huawei":
            print(f"Restoring configuration on Huawei device...")
            logging.info(f"Restoring configuration on Huawei device...")
            shell.send("configure replace flash:/restore.cfg\n")
            logging.info(f"Replacing configuration with restore.cfg...")
            time.sleep(2)
            shell.send("commit\n")
            logging.info(f"Committing configuration...")
            time.sleep(1)
            shell.send("save\n")
            logging.info(f"Saving configuration...")
            time.sleep(1)
            shell.send("y\n")  # Confirm save
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
    logging.info("Script started.")
    # Load YAML configuration file  
    with open("devices.yaml", "r") as f:
        data = yaml.safe_load(f)
    logging.info("YAML configuration file loaded.")
    root_dir = data['directory']
    logging.info("Starting backup and restore operations...")
    # Iterate through devices and perform backup or restore
    for device in data['devices']:
        try:
            if 'restore_file_path' in device:
                # Perform restore operation
                logging.info(f"Restoring configuration for device {device['ip']}...")
                print(f"Restoring configuration for device {device['ip']}...")
                perform_restore(device, root_dir)
            else:
                logging.info(f"Backing up configuration for device {device['ip']}...")
                print(f"Backing up configuration for device {device['ip']}...")
                # Perform backup operation
                perform_backup(device, root_dir)
        except Exception as e:
            logging.error(f"Error processing device {device['ip']}: {str(e)}")
            print(f"Error processing device {device['ip']}: {str(e)}")
        logging.info(f"Operation completed for device {device['ip']}")
        print(f"Operation completed for device {device['ip']}") 
        
    # Print summary
    print("\nOperations completed.")
    print("Saving log...")
 
 
if __name__ == "__main__":
    main()