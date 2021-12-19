# Get-log4j-Windows-local.ps1
  
 Identify all log4j components on a single local windows servers. CVE-2021-44228. A single use copy - see https://github.com/KeysAU/Get-log4j-Windows.ps1 for multi computer.
 
 [Apache log4j](https://logging.apache.org/log4j/2.x/)
 
 [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2021-44228)

# Script Running:

![image](https://user-images.githubusercontent.com/38932932/146667594-aaed6dfc-14d9-4e59-b879-ab128f7c95b0.png)

# Export:

Columns A - I:
![image](https://user-images.githubusercontent.com/38932932/146667638-20cbe4d7-118d-40ad-8edb-7a79c4a205f4.png)

Continued:
![image](https://user-images.githubusercontent.com/38932932/146667684-71ffdc04-19db-49cd-8009-9fc492032791.png)


# Description: 
              Local run version for a single server.            
              Sets up working directory C:\Temp\log4j on local server.
              Recursevly scans all drives for .jar containers.
              Extracts all .jar with 7-zip.exe to C:\temp\log4j\Extracted           
              Gets version number of log4j version.
              Checks if log4j jindiLookup.class file exists of log4j version.
              Scans all local listening IP ports and attempts to exploit with http header.
              Captures failed ps jobs, and closes stuck jobs.
              Dynamically creates csv of where embedded log4j module was located, 
                  if web exploitation was possible and if contains jindilookup.class file.
				
# Created for: 
              Identifying all log4j components on local windows server. CVE-2021-44228

# Dependencies: 
              You must install 7-zip.exe in C:\support\tools\7-zip on the local server (x32 bit suggested)
              PowerShell 5.0+
              Must run as a local admin or equivalent permissions to scan all drives

# Change Log:
        15-Dec-2021  -Change Notes: Initial local copy version.
        19-Dec-2021  -Change Notes: Added scanning for jindiLookup.class
        19-Dec-2021  -Change Notes: Added local listening port scan and exploitation attempt

# Notes: 
        No modification, will out out of the box. Note you still need 7zip.
	
# Licence:
	Open-sourced software licensed under the MIT license.

# Author:
         Keith Waterman
# Date : 
        19-Dec-2021
