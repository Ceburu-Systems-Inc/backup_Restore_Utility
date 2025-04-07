import subprocess
import logging

def run_powershell_command(command):
    try:
        # Prepare the startup info for subprocess
        st_inf = subprocess.STARTUPINFO()
        st_inf.dwFlags = st_inf.dwFlags | subprocess.STARTF_USESHOWWINDOW
        print(command)
        # Execute the PowerShell command
        sub_proc = subprocess.Popen(
            ["powershell.exe", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            startupinfo=st_inf,
            shell=True
        )
        
        # Capture the response and errors
        response, errs = sub_proc.communicate()

        # If there are errors, log and return them
        if errs:
            status = "Error"
            response = errs
        else:
            status = "Success"
        
        # Decode the output
        output = response.decode('utf8').strip()
        
        # Return the status and output
        return {"status": status, "output": output}
    
    except Exception as e:
        logging.error(f"Error occurred while running PowerShell command: {e}")
        return {"status": "Error", "output": str(e)}

# Example usage of the method to manually run a PowerShell command
command = r'&".\dist\Backup_Restore_Switches_Routers_Utility_Agent.exe" --id "429" --routerip "192.168.30.201" --username "admin" --password "P`$`$4Cbr1!!" --devicename "CEBURU-CAT9200" --backup_type "Own Network" --restore_file_path "None" --aws_bucket_name "None" --aws_access_key "None" --aws_secret_key "None" --token "933e4f010ec25e7192513807761abfb08bee90e0" --api_url "http://192.168.30.238:8000/network/universal-backup-upload/"'  
result = run_powershell_command(command)
print(f"Status: {result['status']}")
print(f"Output: {result['output']}")
