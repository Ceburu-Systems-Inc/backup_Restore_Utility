import paramiko
import time
import os
import yaml
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

def detect_vendor(shell):
    # Send a newline to get the prompt
    shell.send("\n")
    time.sleep(1)
    output = shell.recv(1000).decode()
    
    if '>' in output or '#' in output:
        return "cisco"
    elif '[' in output and ']' in output:
        return "huawei"
    elif '%' in output:
        return "juniper"
    else:
        return "Unknown"

def detect_device_details(shell, vendor):
    if vendor == "cisco":
        shell.send("show version\n")
    elif vendor == "juniper":
        shell.send("show chassis hardware\n")
    elif vendor == "huawei":
        shell.send("display version\n")
    else:
        raise ValueError(f"Unsupported vendor: {vendor}")
    time.sleep(3)
    output = shell.recv(65535).decode("utf-8")

    model = "Unknown"
    os_version = "Unknown"

    for line in output.lower().splitlines():
        if vendor == "cisco":
            if "model number" in line or ("cisco" in line and "model" in line):
                model = line.split(":")[-1].strip()
            if "cisco ios software" in line or "ios-xe" in line:
                os_version = line.strip()
            if "nx-os" in line:
                os_version = "NX-OS"
            if "adaptive security appliance" in line:
                os_version = "ASA"
            if "ios xr" in line:
                os_version = "IOS-XR"
        elif vendor == "juniper":
            if "model:" in line:
                model = line.split(":")[-1].strip()
            if "junos" in line:
                os_version = line.strip()
        elif vendor == "huawei":
            if "device model" in line or "vrp" in line:
                model = line.split(":")[-1].strip()
            if "version" in line and "vrp" in line:
                os_version = line.strip()
    return model, os_version


def get_backup_command(vendor, os_version, model):
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


def detect_copy(device, root_dir, log):
    ip = device['ip']
    username = device['username']
    password = device['password']
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    vendor = None  # Initialize outside try block

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
        vendor = detect_vendor(shell)
        model, os_version = detect_device_details(shell, vendor)
        print(f"Detected vendor: {vendor}, model: {model}, OS version: {os_version}")
        command = get_backup_command(vendor, os_version, model)
        if not command:
            raise Exception(f"Unsupported vendor: {vendor}")

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
        
        log[ip] = {
            "status": "success",
            "vendor": vendor,
            "model": model,
            "os_version": os_version,
            "timestamp": timestamp
        }

        return vendor  # ✅ Return here on success

    except Exception as e:
        log[ip] = {"status": "failed", "error": str(e)}
        return None  # Optionally return None on failure

    finally:
        try:
            shell.close()
        except:
            pass

        
def backup_to_remote(device, root_dir, log, vendor):
    ip = device['ip']
    username = device['username']
    password = device['password']
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        ssh = connect_ssh(ip, username, password)
        print(f"Connected to {ip}...")
       
    #     # Use SCP to copy the file from the device
        scp = SCPClient(ssh.get_transport())
        print(f"Copying backup file from device to local directory...")
        vendor_dir = os.path.join(root_dir, vendor)
        os.makedirs(vendor_dir, exist_ok=True)
        local_file = os.path.join(vendor_dir, f"{ip}_{vendor}_{timestamp}.cfg")

        if vendor == "cisco":
            remote_file = "flash:/backup_new.cfg"
        elif vendor == "juniper":
            remote_file = "/var/tmp/backup_new.cfg"
        elif vendor == "huawei":
            remote_file = "flash:/backup_new.cfg"
        else:
            raise Exception(f"Unsupported vendor for SCP: {vendor}")
        print(f"Remote file to copy: {remote_file}")
        scp.get(remote_file)
        os.rename("backup_new.cfg", local_file)

        log[ip] = {
            "status": "success",
            "vendor": vendor,
            "backup_file": local_file
        }
    except Exception as e:
        log[ip] = {"status": "failed", "error": str(e)}
    finally:
        try:
            scp.close()
            time.sleep(2)
            ssh.close()
        except:
            pass
        
def clean_up(device, root_dir, log, vendor):
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
            shell.send("delete flash:/backup_new.cfg\n\n")
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
        log[ip] = {
            "status": "success",
            "vendor": vendor,
        }
    except Exception as e:
        log[ip] = {"status": "failed", "error": str(e)}
    finally:
        try:
            shell.close()
            time.sleep(2)
            print(f"closed cleaup shell.")
        except:
            pass
        
def perform_backup(device, root_dir, log):
    vendor = detect_copy(device, root_dir, log)
    if vendor is not None:
        time.sleep(5)
        backup_to_remote(device, root_dir, log, vendor)
        time.sleep(5)
        clean_up(device, root_dir, log, vendor)
        time.sleep(5)
    else:
        print("Failed to execute backup: Vendor is  None")
    
        

# def perform_restore(device, root_dir, log):
#     ip = device['ip']
#     username = device['username']
#     password = device['password']
#     config_file = device['restore_file_path']

#     try:
#         ssh = connect_ssh_shell(ip, username, password)
#         vendor = detect_vendor(ssh)
            
#         scp = SCPClient(ssh.get_transport(), socket_timeout=0)
#         ssh.get_transport().set_keepalive(30)  # Enable keepalive for legacy protocol support
        
#         # https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-software-releases-122-mainline/46741-backup-config.html
#         if vendor == "cisco":
#             remote_file = "flash:/restore.cfg"
#             scp.put(config_file, remote_file)
#             stdin, stdout, stderr = ssh.exec_command("copy flash:/restore.cfg running-config\n")
#             time.sleep(2)
#             output = stdout.read().decode("utf-8")
#             if "Destination filename" in output:
#                 ssh.exec_command("\n")
#                 time.sleep(1)
#             # Save to startup configuration
#             stdin, stdout, stderr = ssh.exec_command("copy running-config startup-config\n")
#             time.sleep(1)
#             output = stdout.read().decode("utf-8")
#             if "Destination filename" in output:
#                 ssh.exec_command("\n")  # Accept default filename
#                 time.sleep(1)
#         # https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/load.html
#         elif vendor == "juniper":
#             remote_file = "/var/tmp/restore.cfg"
#             scp.put(config_file, remote_file)
#             ssh.exec_command("configure exclusive\n")
#             time.sleep(1)
#             ssh.exec_command("load override /var/tmp/restore.cfg\n")
#             time.sleep(1)
#             ssh.exec_command("commit and-quit\n")
#             time.sleep(1)

#         # https://support.huawei.com/enterprise/en/doc/EDOC1100278246/12f65d97/restoring-the-configuration-file-from-the-storage-medium
#         elif vendor == "huawei":
#             remote_file = "flash:/restore.cfg"
#             scp.put(config_file, remote_file)
#             ssh.exec_command("configure replace flash:/restore.cfg\n")
#             time.sleep(2)
#             ssh.exec_command("commit\n")
#             time.sleep(1)
#             stdin, stdout, stderr = ssh.exec_command("save\n")
#             time.sleep(1)
#             output = stdout.read().decode("utf-8")
#             if "Are you sure to save" in output or "(y/n)" in output:
#                 ssh.exec_command("y\n")
#                 time.sleep(1)
#         log[ip] = {
#             "status": "restored",
#             "config_file": config_file,
#             "vendor": vendor
#         }

#     except Exception as e:
#         log[ip] = {"status": "restore failed", "error": str(e)}
#     finally:
#         try:
#             ssh.close()
#         except:
#             pass
def perform_restore(device, root_dir, log):
    ip = device['ip']
    username = device['username']
    password = device['password']
    config_file = device['restore_file_path']

    try:
        # Step 1: Detect the vendor using SSH
        print(f"Connecting to {ip} to detect vendor...")
        shell = connect_ssh_shell(ip, username, password)
        vendor = detect_vendor(shell)
        shell.close()
        time.sleep(5)
        print(f"Detected vendor: {vendor}")

        # Step 2: Use SCP to copy the restore file to the device
        print(f"Copying restore file to {ip}...")
        ssh = connect_ssh(ip, username, password)
        # ssh.get_transport().set_keepalive(30)  # Enable keepalive for legacy protocol support

        # Increase SCP timeout and add progress callback
        def progress(filename, size, sent):
            print(f"[*] SCP Progress: {filename}, {sent}/{size} bytes transferred")

        scp = SCPClient(ssh.get_transport(), socket_timeout=30, progress=progress)

        if vendor == "cisco":
            remote_file = "flash:/restore.cfg"
        elif vendor == "juniper":
            remote_file = "/var/tmp/restore.cfg"
        elif vendor == "huawei":
            remote_file = "flash:/restore.cfg"
        else:
            raise Exception(f"Unsupported vendor for SCP: {vendor}")

        print(f"Uploading {config_file} to {remote_file} on {ip}...")
        scp.put(config_file, remote_file)
        scp.close()
        ssh.close()
        print(f"Restore file copied to {ip}")
        time.sleep(5)
        # Step 3: Use SSH to apply the restore configuration
        print(f"Applying restore configuration on {ip}...")
        shell = connect_ssh_shell(ip, username, password)
        if vendor == "cisco":
            print(f"Restoring configuration on Cisco device...")
            shell.send("copy flash:/restore.cfg running-config\n")
            time.sleep(2)
            shell.send("\n")  # Accept default filename
            time.sleep(1)
            shell.send("copy running-config startup-config\n")
            time.sleep(1)
            shell.send("\n")  # Accept default filename
            time.sleep(1)
        elif vendor == "juniper":
            print(f"Restoring configuration on Juniper device...")
            shell.send("configure exclusive\n")
            time.sleep(1)
            shell.send("load override /var/tmp/restore.cfg\n")
            time.sleep(1)
            shell.send("commit and-quit\n")
            time.sleep(1)
        elif vendor == "huawei":
            print(f"Restoring configuration on Huawei device...")
            shell.send("configure replace flash:/restore.cfg\n")
            time.sleep(2)
            shell.send("commit\n")
            time.sleep(1)
            shell.send("save\n")
            time.sleep(1)
            shell.send("y\n")  # Confirm save
            time.sleep(1)

        print(f"Restore configuration applied on {ip}")

        log[ip] = {
            "status": "restored",
            "config_file": config_file,
            "vendor": vendor
        }

    except Exception as e:
        print(f"Restore failed on {ip}: {str(e)}")
        log[ip] = {"status": "restore failed", "error": str(e)}
    finally:
        try:
            shell.close()
            print(f"Closed SSH connection to {ip}")
        except:
            print(f"Failed to close SSH connection to {ip}")


def main():
    with open("devices.yaml", "r") as f:
        data = yaml.safe_load(f)

    root_dir = data['directory']
    log = {}

    for device in data['devices']:
        try:
            if 'restore_file_path' in device:
                perform_restore(device, root_dir, log)
            else:
                perform_backup(device, root_dir, log)
        except Exception as e:
            log[device['ip']] = {"status": "error", "error": str(e)}
    # Print summary
    print("\nSummary of operations:")
    for ip, details in log.items():
        print(f"  - {ip}: {details}")
    print("\nOperations completed.")
    print("Saving summary log...")
    # Save log 
    os.makedirs(root_dir, exist_ok=True) 
    log_file = os.path.join(root_dir, f"summary_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml")
    with open(log_file, "w") as f:
        yaml.dump(log, f, default_flow_style=False)
    print(f"Summary log saved to {log_file}")


if __name__ == "__main__":
    main()
