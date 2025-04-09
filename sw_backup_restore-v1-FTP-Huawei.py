from datetime import datetime
from scp import SCPClient
import subprocess, re, ftplib, csv, logging, os, time, paramiko

 
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
 
def check_and_bypass_confirmation(shell, timeout=15, prompt_response="Y"):
    start_time = time.time()
    output = ""
    while True:
        if shell.recv_ready():
            chunk = shell.recv(65535).decode("utf-8")
            output += chunk
            print(chunk, end="")  # For visibility during testing

            # Detect common confirmation prompts
            if re.search(r'\[Y/N\]|\(Y/N\)|[Yy]es/[Nn]o|continue\?', chunk):
                logging.info("confirmation prompt detected in: " + chunk)
                print(chunk, end="")  # For visibility during testing
                print("Confirmation prompt detected. Sending:", prompt_response)
                logging.info("Confirmation prompt detected. Sending: " + prompt_response)
                shell.send(prompt_response + '\n')
                time.sleep(1)

        if time.time() - start_time > timeout:
            print("Timeout reached")
            break

    return output

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
 
 
def detect_copy(device):
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
 
       
def backup_to_remote(device, root_dir, vendor):
    ip = device['ip']
    username = device['username']
    password = device['password']
   
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logging.info(f"Connecting to {ip}...")
    try:
       
       
    #     # Use SCP to copy the file from the device
        if vendor != "huawei":
            ssh = connect_ssh(ip, username, password)
            print(f"Connected to {ip}...")
            scp = SCPClient(ssh.get_transport(), socket_timeout=1000)
            logging.info(f"SCP session created for {ip}...")
        print(f"Copying backup file from device to local directory...")
        logging.info(f"Copying backup file from device to local directory...")
        vendor_dir = os.path.join(root_dir, vendor)
        os.makedirs(vendor_dir, exist_ok=True)
        local_file = os.path.join(vendor_dir, f"{ip}_{vendor}_{timestamp}.cfg")
 
        if vendor == "cisco":
            remote_file = "backup_new.cfg"
        elif vendor == "juniper":
            remote_file = "backup_new.cfg"
        elif vendor == "huawei":
            remote_file = "backup.cfg"
        else:
            logging.error(f"Unsupported vendor for SCP: {vendor}")
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        logging.info(f"Remote file to copy: {remote_file}")
        print(f"Remote file to copy: {remote_file}")
        if vendor != "huawei":
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
        else:
            shell = connect_ssh_shell(ip, username, password)
            print(f"Connected to {ip}...")
            logging.info('Connected to huawei over ssh')
            time.sleep(1)
            shell.recv(1000)
            shell.send("terminal length 0\n")
            time.sleep(1)  # Give some time for the command to execute
            shell.send("screen-length 0 temporary\n")
            time.sleep(1)  # Give some time for the command to execute
            shell.send("set cli screen-length 0\n")
            time.sleep(1)
            local_file = os.path.join(vendor_dir, f"{ip}_{vendor}_{timestamp}.cfg")
            logging.info(f"Preparing to copy backup file from Huawei device to local directory: {local_file}")
            time.sleep(1)
            shell.recv(1000)
            command = f"more {remote_file}\n"
            shell.send(command)
            time.sleep(3)  # Give some time for the command to execute and output to be generated
            # Capture the output from the shell
            stdout = shell.recv(65535).decode("utf-8").splitlines()  # Capture the output of the command
            #ignoring line 1 from stdout
            if len(stdout) > 0:
                stdout = stdout[1:-1] # Ignore the first line which is usually a prompt or header
            logging.info(f"Executing command on Huawei device: {command}")
            time.sleep(3)
            # Capture output and save locally
            with open(local_file, "w") as f:
                for line in stdout:
                    f.write(line + "\n")
            
            logging.info(f"Backup file saved locally: {local_file}")
            shell.close()

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
    vendor = detect_copy(device)
    if vendor is not None:
        logging.info(f"Vendor detected: {vendor}")
        time.sleep(5)
        backup_to_remote(device, root_dir, vendor)
        logging.info(f"Backup completed for vendor: {vendor}")
        time.sleep(5)
        # clean_up(device, log, vendor)
        # time.sleep(5)
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
        vendor = detect_vendor(shell)
        shell.close()
        time.sleep(5)
        print(f"Detected vendor: {vendor}")
        logging.info(f"Detected vendor: {vendor}")
        logging.info(f"Restoring configuration for device {ip}...")
        
        # Special handling for Huawei devices
        if vendor == "huawei":
            perform_huawei_restore(device, config_file)
            return
            
        # Step 2: Use SCP to copy the restore file to the device for non-Huawei devices
        print(f"Copying restore file to {ip}...")
        logging.info(f"Copying restore file to {ip}...")
        
        # Define progress callback function
        def progress(filename, size, sent):
            print(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")
            logging.info(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")  
 
        if vendor == "cisco":
            remote_file = "restore.cfg"
        elif vendor == "juniper":
            remote_file = "/var/tmp/restore.cfg"
        else:
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        
        scp = None
        try:
            ssh = connect_ssh(ip, username, password)
            logging.info(f"Remote file to copy: {remote_file}")
            print(f"Uploading {config_file} to {remote_file} on {ip}...")
            logging.info(f"Uploading {config_file} to {remote_file} on {ip}...")
            logging.info(f"Creating SCP session for {ip}...")
            scp = SCPClient(ssh.get_transport(), socket_timeout=100, progress=progress)
            logging.info(f"SCP session created for {ip}...")
            scp.put(config_file, remote_file)
            print(f"File successfully uploaded to {ip}")
            logging.info(f"File successfully uploaded to {ip}")
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
            shell.send("configure\n")
            output = shell.recv(65535).decode("utf-8")
            logging.info(f"Received output for configuration mode: {output}")
            
            logging.info(f"Entering exclusive configuration mode...")
            time.sleep(3)
            shell.send("load override /var/tmp/restore.cfg\n")

            output = shell.recv(65535).decode("utf-8")
            logging.info(f"Received output for configuration mode: {output}")
            logging.info(f"Loading configuration from restore.cfg...")
            time.sleep(6)

            output = shell.recv(65535).decode("utf-8")
            logging.info(f"Received output for configuration mode: {output}")
            
            shell.send("commit\n")
            # Wait for commit to complete
            logging.info(f"Committing configuration...")
            time.sleep(3)  # Initial delay

            # Wait for commit response
            start_time = time.time()
            timeout = 60
            commit_complete = False

            while time.time() - start_time < timeout and not commit_complete:
                if shell.recv_ready():
                    output = shell.recv(65535).decode("utf-8")
                    logging.info(f"Commit output: {output}")
                    
                    # Check for completion indicators
                    if "commit complete" in output.lower() or "configuration committed" in output.lower():
                        commit_complete = True
                        logging.info("Commit completed successfully")
                    elif "error" in output.lower() or "failed" in output.lower():
                        logging.error(f"Commit error: {output}")
                        raise Exception(f"Configuration commit failed: {output}")
                time.sleep(1)

            if not commit_complete:
                logging.warning("Commit operation timed out")
            
            
            shell.send("exit\n")
            output = shell.recv(65535).decode("utf-8")
            logging.info(f"Received output for exiting configuration mode: {output}")
            time.sleep(2)
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


def perform_huawei_restore(device, config_file):
    """Separate function for Huawei device restore using command line FTP"""
    
    ip = device['ip']
    username = device['username']
    password = device['password']
    
    config_filename = os.path.basename(config_file)
    print(f"Restoring configuration on Huawei device {ip} using FTP...")
    logging.info(f"Restoring configuration on Huawei device {ip} using FTP...")
    
    # Step 1: Upload the config file using command line FTP
    try:
        
        print(f"Starting FTP process to upload configuration file {config_filename}...")
        logging.info(f"Starting FTP process to upload configuration file {config_filename}...")
        # Start FTP process with direct IP connection
        ftp_process = subprocess.Popen(['ftp', ip],
                                      stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      universal_newlines=True)

        # Wait for username prompt and send username
        time.sleep(2)  # Give time for connection and prompt
        ftp_process.stdin.write(f"{username}\n")
        ftp_process.stdin.flush()
        logging.info(f"Sent username: {username}")

        # Wait for password prompt and send password
        time.sleep(1)
        ftp_process.stdin.write(f"{password}\n")
        ftp_process.stdin.flush()
        logging.info("Sent password")

        # Wait for login to complete
        time.sleep(2)

        # Send binary mode command
        ftp_process.stdin.write("binary\n")
        ftp_process.stdin.flush()
        logging.info("Set binary transfer mode")
        time.sleep(1)

        # Send put command to upload file
        ftp_process.stdin.write(f"put {config_file} {config_filename}\n")
        ftp_process.stdin.flush()
        logging.info(f"Uploading file {config_file} as {config_filename}")
        time.sleep(3)  # Give more time for file upload

        # Exit FTP session
        ftp_process.stdin.write("quit\n")
        ftp_process.stdin.flush()
        logging.info("Sent quit command to close FTP session")
        
        # Close stdin to signal we're done sending commands
        ftp_process.stdin.close()
        
        # Wait for process to complete and get output
        stdout, stderr = ftp_process.communicate()
        
        # Check if successful
        if ftp_process.returncode != 0:
            print(f"FTP stdout: {stdout}")
            print(f"FTP stderr: {stderr}")
            raise Exception(f"FTP process failed with return code {ftp_process.returncode}")
        
        print(f"File {config_filename} successfully uploaded via FTP")
        logging.info(f"File {config_filename} successfully uploaded via FTP")
        
    except Exception as e:
        print(f"FTP upload failed on {ip}: {str(e)}")
        logging.error(f"FTP upload failed on {ip}: {str(e)}")
        raise
    
    # Step 2: SSH to set startup configuration and reboot
    try:
        shell = connect_ssh_shell(ip, username, password)
        print(f"Setting startup configuration and rebooting...")
        logging.info(f"Setting startup configuration and rebooting...")
        logging.info("Bypassing password change prompt, sending 'N' to bypass if any found...")
        check_and_bypass_confirmation(shell, timeout=5, prompt_response="N")

        time.sleep(1)
        output = shell.recv(65535).decode("utf-8")
        logging.info(f"Response after bypassing password prompt: {output}")
        
        # Set the uploaded file as startup configuration
        shell.send(f"startup saved-configuration {config_filename}\n")
        logging.info(f"Setting {config_filename} as startup configuration...")
        # Wait to receive command prompt or confirmation request
        time.sleep(2)
        output = shell.recv(65535).decode("utf-8")
        logging.info(f"Response after setting startup configuration: {output}")
        check_and_bypass_confirmation(shell, timeout=15, prompt_response="Y")
       
        logging.info("Sending reboot command...")
         # Reboot the device
        shell.send("reboot\n")
        time.sleep(1)
        check_and_bypass_confirmation(shell, timeout=15, prompt_response="Y")
        logging.info("Reboot command sent, waiting for confirmation...")
       
        print(f"Huawei device {ip} is now rebooting with the new configuration")
        logging.info(f"Huawei device {ip} is now rebooting with the new configuration")
        
    except Exception as e:
        print(f"Setting startup configuration failed on {ip}: {str(e)}")
        logging.error(f"Setting startup configuration failed on {ip}: {str(e)}")
    finally:
        try:
            shell.close()
            print(f"Closed SSH connection to {ip}")
            logging.info(f"Closed SSH connection to {ip}")
        except:
            pass
 
 
def main():
    version = "1.0.0"
    print(f"SW Backup and Restore Script Version: {version}")
    # Load CSV file and parse data
    with open("devices.csv", "r") as f:
        reader = csv.DictReader(f)
        devices = []
        default_username = None
        default_password = None
        default_storage_path = os.getcwd() + "/output"
        for row in reader:
            if row["IP Address"] == "":
                # Capture default username and password
                if "Default Username" in row["Username"]:
                    default_username = row["Password"]
                elif "Default Password" in row["Username"]:
                    default_password = row["Password"]
                elif "Default Storage Path" in row["Username"]:
                    default_storage_path = row["Password"] or default_storage_path
            else:
                # Use default username and password if missing
                device = {
                    "ip": row["IP Address"],
                    "username": row["Username"] if row["Username"] else default_username,
                    "password": row["Password"] if row["Password"] else default_password,
                }
                if row["Restore Path"]:
                    device["restore_file_path"] = row["Restore Path"]
                devices.append(device)

    data = {"directory": default_storage_path, "devices": devices}
    # Change log file path to the default storage directory
    log_folder = os.getcwd() + "/logs"
    os.makedirs(log_folder, exist_ok=True)  # Create logs directory if it doesn't exist
    log_file_path = os.path.join(log_folder, f'script_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info("Starting SW Backup and Restore Script...")
    logging.info(f"Version: {version}")
    logging.info("CSV configuration file loaded.")
    root_dir = data['directory']
    logging.info("Starting backup and restore operations...")
    # Iterate through devices and perform backup or restore
    for device in data['devices']:
        try:
            if 'restore_file_path' in device:
                # Perform restore operation
                logging.info(f"Restoring configuration for device {device['ip']}...")
                print(f"Restoring configuration for device {device['ip']}...")
                perform_restore(device)
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