import paramiko, time, os, sys, shutil, requests, logging, argparse, boto3, re, subprocess
from datetime import datetime
from scp import SCPClient


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

def check_and_bypass_confirmation(shell, timeout=15, prompt_response="Y", ):
    timeout = timeout
    start_time = time.time()
    output = ""
    try:
        prompt_counter = 0
        last_prompt = ""
        max_prompts = 3  # Maximum number of times to respond to similar prompts
        
        while (time.time() - start_time) < timeout:
            if shell.recv_ready():
                chunk = shell.recv(65535).decode("utf-8")
                output += chunk
                print(chunk, end="")  # For visibility during testing
                logging.info("Received chunk: " + chunk)
                
                # Check for specific confirmation prompts
                if re.search(r'\[Y/N\]|\(Y/N\)|[Yy]es/[Nn]o|continue\?', chunk) and "configuration will be saved to the configuration file" not in chunk:
                    logging.info("confirmation prompt detected in: " + chunk)
                    
                    # Check if this is the same prompt repeating
                    if chunk.strip() == last_prompt.strip():
                        prompt_counter += 1
                        if prompt_counter >= max_prompts:
                            logging.warning("Detected possible infinite prompt loop, breaking out")
                            break
                    else:
                        prompt_counter = 0
                        last_prompt = chunk
                        
                    print("Confirmation prompt detected. Sending:", prompt_response)
                    logging.info("Confirmation prompt detected. Sending: " + prompt_response)
                    shell.send(prompt_response + '\n')
                    time.sleep(0.5)  # Small delay to let the response be processed

                elif "configuration will be saved to the configuration file" in chunk:
                    print("Configuration will be saved to the configuration file. Sending:N" )
                    logging.info("Configuration will be saved to the configuration file. Sending: N")
                    shell.send("N\n")
                    time.sleep(0.5)  # Small delay to let the response be processed
                # Check for other types of prompts that may require confirmation
                
                elif re.search(r'Are you sure|Proceed|Confirm', chunk):
                    logging.info("Additional confirmation prompt detected in: " + chunk)
                    
                    # Check if this is the same prompt repeating
                    if chunk.strip() == last_prompt.strip():
                        prompt_counter += 1
                        if prompt_counter >= max_prompts:
                            logging.warning("Detected possible infinite prompt loop, breaking out")
                            break
                    else:
                        prompt_counter = 0
                        last_prompt = chunk
                        
                    print("Additional confirmation prompt detected. Sending:", prompt_response)
                    logging.info("Additional confirmation prompt detected. Sending: " + prompt_response)
                    shell.send(prompt_response + '\n')
                    time.sleep(0.5)
            
            # Small delay to prevent CPU spinning
            time.sleep(0.1)
            
    except Exception as e:
        logging.error(f"Error in check_and_bypass_confirmation: {str(e)}")
        print(f"Error in confirmation handling: {str(e)}")
    
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
            scp = SCPClient(ssh.get_transport(), socket_timeout=1000)
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
        
        time.sleep(1)
        # check_and_bypass_confirmation(shell, timeout=5, prompt_response="N")
        shell.send("N\n")
        
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
    # Setting up logging to file with timestamp

    if getattr(sys, 'frozen', False):
       current_file_path = os.path.abspath(sys.argv[0])  # The path to the .exe file
    else:
       current_file_path = os.path.abspath(__file__)

    current_file_folder = os.path.dirname(current_file_path)  # The folder where the .exe file is located
    # getting current file path 
    temp_output_dir = os.path.join(current_file_folder, 'temp_output_backup_restore')
    os.makedirs(temp_output_dir, exist_ok=True)
    log_file_path = os.path.join(temp_output_dir,f'script_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    logging.basicConfig(
        filename=log_file_path,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    # Setting up argument parser for named arguments
    parser = argparse.ArgumentParser(description="Network Device Configuration Manager - Backup and Restore Tool. Sample usage: ./Backup_Restore_Switches_Routers_Utility_Agent.exe --id \"123\" --devicename \"router1\" --routerip \"192.168.1.1\" --username \"admin\" --password \"pass\" --backup_type \"Own Network\" --restore_file_path \"None\" --aws_bucket_name \"my-bucket\" --aws_access_key \"key\" --aws_secret_key \"secret\" --api_url \"https://api.example.com\" --token \"apikey\"")
    parser.add_argument("--id", required=True, help="Backup command ID")
    parser.add_argument("--devicename", required=True, help="Device name")
    parser.add_argument("--routerip", required=True, help="Device IP address")
    parser.add_argument("--username", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--backup_type", required=True, help="Backup Type - Ceburu Network / Own Network")
    parser.add_argument("--restore_file_path", default=None, help="Path / url to the restore file")
    parser.add_argument("--aws_bucket_name", default=None, help="AWS bucket name")
    parser.add_argument("--aws_access_key", default=None, help="AWS access key")
    parser.add_argument("--aws_secret_key", default=None, help="AWS secret key")
    parser.add_argument("--api_url", required=True, help="API URL for backend server to send backup file and log file")
    parser.add_argument("--token", required=True, help="API key for backend server")
    try:
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
        api_url = args.api_url
        api_key = args.token

    except Exception as e:
        logging.error(f"Error parsing arguments: {e}")
        print(f"Error parsing arguments: {e}")
        parser.print_help()
        return
    
    logging.info("Starting Network Device Configuration Manager - Backup and Restore Tool")
    # command = f"{id} {routerip} {username} {password} {devicename} {backup_type} {restore_file_path} {aws_bucket_name} {aws_access_key} {aws_secret_key} {token} {api_url}"
     

    logging.info("Starting backup/restore operation for device: {}".format(device_name))
    logging.info(f"Backup command ID: {backup_command_id}")
    logging.info(f"Device IP: {ip}")
    logging.info(f"Username: {username}")
    logging.info(f"Backup Type: {backup_type}")
    logging.info(f"Restore file path: {restore_file_path}")
    logging.info(f"AWS bucket name: {aws_bucket_name}")
    logging.info(f"using  temorary output directory: {temp_output_dir}")
    logging.info(f"API URL: {api_url}")
    logging.info(f"API key: {api_key}")
    logging.info(f"password: {password}")
    logging.info(f"username: {username}")
    local_backup_file = f'{backup_command_id}_{device_name}.cfg' # Default backup file name based on backup_command_id and device_name
    logging.info("Starting backup / restore operation...")
    print("Starting backup / restore operation...")
    local_restore_file = None

    try:

        # Check if restore_file_path is provided for restore operation
        if restore_file_path != None and restore_file_path!= "None":
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
    except Exception as e:
        logging.error(f"Error during backup/restore operation: {e}")
        print(f"Error during backup/restore operation: {e}")   
   # closing log file
    logging.info("Closing log file...")
    print("Closing log file...")
    
    # Get a reference to the root logger and close all handlers
    root_logger = logging.getLogger()
    # Shutdown logging system completely
    
    for handler in root_logger.handlers:
        handler.close()
        root_logger.removeHandler(handler)
    time.sleep(10)
    logging.shutdown()
    time.sleep(2)
    try:
        if not (restore_file_path != None and restore_file_path!= "None"):
            backup_file_size = "0 bytes"
            if os.path.exists(os.path.join(temp_output_dir,local_backup_file)):
                backup_file_size_with_units = os.path.getsize(os.path.join(temp_output_dir,local_backup_file))
                if backup_file_size_with_units < 1024:
                    backup_file_size = f"{backup_file_size_with_units} bytes"
                elif backup_file_size_with_units < 1024**2:
                    backup_file_size = f"{backup_file_size_with_units / 1024:.2f} KB"
                elif backup_file_size_with_units < 1024**3:
                    backup_file_size = f"{backup_file_size_with_units / 1024**2:.2f} MB"
                else:
                    backup_file_size = f"{backup_file_size_with_units / 1024**3:.2f} GB"
            
            print(f"SourceSize : {backup_file_size}")
            if backup_type.lower() == "ceburu network":
                print(f"Uploading backup file to AWS S3 bucket {aws_bucket_name}...")
                s3 = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
                s3.upload_file(os.path.join(temp_output_dir,local_backup_file), aws_bucket_name, os.path.basename(local_backup_file))
                print(f"Backup file uploaded to AWS S3 bucket {aws_bucket_name}")
                print(f"Uploading log file to AWS S3 bucket {aws_bucket_name}...")
                s3.upload_file(log_file_path, aws_bucket_name, os.path.basename(log_file_path))
                print(f"Log file uploaded to AWS S3 bucket {aws_bucket_name}")
                # adding logigc to send log file to backend server
                with open(log_file_path, 'rb') as log_file:
                    log_content = log_file.read()
                    # Prepare data to match endpoint's expected format
                    data = {
                        'backup_id': backup_command_id,
                        'type': backup_type,
                        'version': '1.0'
                    }
                    
                    headers = {'Authorization': "Token " + api_key}
                    response = requests.post(api_url, files={'log_file': (os.path.basename(log_file_path), log_content, 'text/plain')}, data=data, headers=headers)
                    if response.status_code == 200:
                        print(f"Log file uploaded to backend server")
                    else:
                        print(f"Failed to upload log file to backend server: {response.status_code}")

            elif backup_type.lower() == "own network":
                # sending backup and log file to backend server
                    with open(os.path.join(temp_output_dir,local_backup_file), 'rb') as backup_file, open(log_file_path, 'rb') as log_file:
                        backup_content = backup_file.read()
                        log_content = log_file.read()
                    
                    files = {
                        'backup_file': (os.path.basename(local_backup_file), backup_content, 'application/octet-stream'),
                        'log_file': (os.path.basename(log_file_path), log_content, 'text/plain')
                    }
                    headers = {'Authorization': "Token " + api_key}
                    # Prepare data to match endpoint's expected format
                    data = {
                        'backup_id': backup_command_id,
                        'type': backup_type,
                        'version': '1.0'  # Add version information if available
                    }
                    
                    response = requests.post(api_url, files=files, data=data, headers=headers)
                    if response.status_code == 200:
                        print(f"Backup file and log file uploaded to backend server")
                    else:
                        print(f"Failed to upload files to backend server: {response.status_code}")
    except Exception as e:
        print(f"Error uploading files: {e}")

    try:
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
            shutil.rmtree(temp_output_dir)
            print(f"Temp directory {temp_output_dir} deleted")
            print(f"Temp directory {temp_output_dir} deleted")

    except Exception as e:
        print(f"Error deleting files: {e}")
        
if __name__ == "__main__":
    main()