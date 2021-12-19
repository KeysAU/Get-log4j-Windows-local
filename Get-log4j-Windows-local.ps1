#####################################################################################
#
#     Get-log4j-Windows-local-v1.ps1
#
# Author: Keith Waterman
# Date : 19-Dec-2021
#
#
# Description: Made for CVE-2021-44228
#              Local run version for single server.#              
#              Sets up working directory C:\Temp\log4j on remote servers and copy's over 7zip.exe
#              Recursevly scans all drives for .jar containers.
#              Extracts all .jar with 7-zip.exe to C:\temp\log4j\Extracted           
#              Gets version number of log4j version.
#              Checks if log4j jindiLookup.class file exists of log4j version.
#              Scans all local listening IP ports and attempts to exploit with http header.
#              Dynamically creates csv of where embedded log4j module was located, if web exploitation was possible and if contains jindilookup.class file.
#              Captures failed ps jobs, and closes stuck jobs.
#				
# Created for: Identifying all log4j components across on local windows servers. CVE-2021-44228
#
#
# Dependencys: 7-zip.exe must be installed in C:\support\tools\7-zip from command and control server (x32 bit suggested)
#              Powershell 5.0+
#              Must be run as a local admin or equivelent permissions to scan all drives
#
# Change Log:
#    15-Dec-2021  -Change Notes: Initial version
#    19-Dec-2021  -Change Notes: Added scanning for jindiLookup.class
#    19-Dec-2021  -Change Notes: Added local listening port scan and exploitation attempt
#
# Notes: N/A

#$Cred = Get-Credential
$HostServer = (Get-WmiObject Win32_ComputerSystem).name

if (!(($PSVersionTable.PSVersion.Major) -ge "5")) {
    Write-Host -ForegroundColor Yellow "Powershell version to low, requires 5.0+"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Powershell 5.0+. Proceeding.." }

if (!(Test-Path -Path "c:\Support\Tools\7-zip")) {
    Write-Host -ForegroundColor Yellow "7-zip tools not installed to C:\Support\Tools\7-zip"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please Install 7-zip x32 to C:\Support\Tools"
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: 7-zip tools installed. Proceeding.." }

<# Credentials
If ([string]::IsNullOrEmpty($Cred)) {
    Write-Host -ForegroundColor Yellow "No credentials detected, uncomment #`$Cred"
    Write-Host -ForegroundColor Red "ERROR: Stopping Script."
    Write-Host -ForegroundColor Yellow "Please enter in domain admin credentials."
    Break
}
Else { Write-Host -ForegroundColor Green "PreReq: Credentials Detected. Proceeding.." }
#>

#####################
#Setup Host Server Working Directories csv
#####################

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j")) {
    mkdir "\\$HostServer\c$\Temp\Log4j" -Force  | Out-Null
}

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j\Extracted")) {
    mkdir "\\$HostServer\c$\Temp\Log4j\Extracted" -Force  | Out-Null
}

if (!(Test-Path -Path "\\$HostServer\c$\Temp\Log4j\log4j-reports")) {
    mkdir "\\$HostServer\c$\Temp\Log4j\log4j-reports" -Force  | Out-Null
}                
               
$ReportObj = @()
write-Host "1.) Getting Local Drives.."
#Get Local Drives
$Local_Drives = Get-PSDrive | Select-Object Root | Where-Object { $_.Root -like "*:*" }
write-Host "2.) Completed."
write-Host "3.) Searching Local Drives.." $Local_Drives.Root
$Jar_Files = @()

Foreach ($DriveLetter in $Local_Drives) {

    $Items = Get-ChildItem -ErrorAction SilentlyContinue -Path $DriveLetter.Root -Recurse | Where-Object { $_.Name -like "*.jar" } |  Select-Object Name, FullName | Where-Object { $_.FullName -like "*log4j*" }
    $Jar_Files += $Items
}                                               

write-Host "4.) Completed."

If (-NOT [string]::IsNullOrEmpty($Jar_Files)) { Write-host "5.) Found .jar files.." } Else {
    write-Host "5.) No .jar Files Found. Exiting." ; 
    $ObjProp0 = @{    
        ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                                FullPath                  = "No .js files found"    
                                JndiLookupClass           = "N/A"
                                Log4JVersion              = "N/A"
                                GroupId                   = "N/A"
                                artifactId                = "N/A"
                                Suspected_Processes       = "N/A"
                                Suspected_Ports           = "N/A"
                                Suspected_LocalAddresses  = "N/A"
                                PSVersion = ($PSVersionTable.PSVersion)
                                Suspected_FullNetworkInfo = "N/A"                        
    }
    $TempObj0 = New-Object -TypeName psobject -Property $ObjProp0
    $ReportObj += $TempObj0
    $ReportObj ; Exit
}
                       
write-Host "6.) Extracing all found .jar files.."

 $Counter = 0

Foreach ($Jar_File in $Jar_Files) {

    $Counter++

    $Var_Jar = $Jar_File.Name.trim(".jar")
    $Var_Jar_Extract = $Jar_File.FullName
    function Expand-7zip(
        [String] $aDirectory, [String] $aZipfile) {
        [string]$pathToZipExe = "C:\Support\Tools\7-Zip\7z.exe";
        [Array]$arguments = "e", "$aZipfile", "-oC:\Temp\Log4j\Extracted\$Counter\$Var_Jar" , "-y";
        & $pathToZipExe $arguments;
    }

    Expand-7zip -aZipfile $("$Var_Jar_Extract") | Out-Null

    $ObjProp0 = [ordered]@{    
        FullPath        = $Jar_File.FullName
        FileName        = $Jar_File.Name    
        ReferenceNumber = $Counter
    }
    New-Object -TypeName psobject -Property $ObjProp0 | Export-csv "C:\Temp\Log4j\Extracted\Report.csv" -NoTypeInformation -Append
}

write-Host "7.) Completed."
write-Host "8.) Searching extracted .jar files.."

write-Host "9.) Completed."
write-Host "10.) Getting NetTCP Connection Info.."
$NetworkStats = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.Process -like "*jav*") -and ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }

write-Host "11.) Completed."

write-Host "12.) Start local host vulnerability scan.."


####
# Web Scanning Start
###


#Get all local listening ports
$NetworkConnections = get-nettcpconnection | Select-Object local*, remote*, state, @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } } | Where-Object { ($_.State -eq "Listen") } | Where-Object { ($_.LocalAddress -eq "127.0.0.1") -and ($_.RemoteAddress -ne "::") }
    
$LocalListeningPorts = @()

Foreach ($NetworkConnection in $NetworkConnections) { 
    
    $NetworkHash = [ordered]@{    
        ServerName   = (Get-WmiObject Win32_ComputerSystem).name
        LocalAddress = $NetworkConnection.LocalAddress
        LocalPort    = $NetworkConnection.LocalPort
        State        = $NetworkConnection.State
        Process      = $NetworkConnection.Process
        httpUrl      = "http://" + $NetworkConnection.LocalAddress + ":" + $NetworkConnection.LocalPort
        httpsUrl     = "https://" + $NetworkConnection.LocalAddress + ":" + $NetworkConnection.LocalPort
                            
    }
    $TempObjNetwork = New-Object -TypeName psobject -Property $NetworkHash 
    $LocalListeningPorts += $TempObjNetwork
}


#Built http listening port url targets
Foreach ($http_LocalListeningPort in $LocalListeningPorts) {

    $Http_Target = $http_LocalListeningPort.httpUrl
    $JsonHeader = @{ 'User-Agent' = '${jndi:ldap://' + $($Http_Target) + '/x}' }

    $ScriptBlockWeb = { $Results = Invoke-WebRequest -Uri $Using:Http_Target -Headers $Using:JsonHeader -UseBasicParsing

        Write-output $Results
    }
    Start-Job -name $http_LocalListeningPort.httpUrl  -ScriptBlock $ScriptBlockWeb | Out-Null
    
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$True} #Ignore ssl errors, only set for this ps session. 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12  #connect over tls1.2

#Built https listening port url targets

<#
Foreach ($https_LocalListeningPort in $LocalListeningPorts[7]) {

    $Https_Target = $https_LocalListeningPort.httpsUrl
    $JsonHeader = @{ 'User-Agent' = '${jndi:ldap://' + $($Http_Target) + '/x}' }

    $ScriptBlockWeb = { $Results = Invoke-WebRequest -Uri $using:Https_Target -Headers $using:JsonHeader -UseBasicParsing

        Write-output $Results
    }
    Start-Job -name $https_LocalListeningPort.httpsUrl  -ScriptBlock $ScriptBlockWeb
    
}
#>


#Start a jobs for each target port. This uses ps jobs so It can close stuck invoke-web commands. Alot of ports crashed during testing.
#loops through infinitly until all jobs complete or stopped.
$WebScan_Results = @()
Do {

    $CountingJobs = (get-job -State Running).count
    $WebScan_RunningJobs = (Get-Job | Where-Object { $_.State -eq "Running" })

    Foreach ($WebScan_RunningJob in $WebScan_RunningJobs) {   

        $WebJobTimeout = 5
        $CurrentTime = get-date
        $TimeoutTime = $WebScan_RunningJob.PSBeginTime
        $TimeoutTime = $TimeoutTime.AddSeconds($WebJobTimeout)

        #The equation here is:
        #if the current time is more than the time the job started + 5 seconds.
        #Then its time we get the info about the job and then stop it
        if ($CurrentTime -gt $TimeoutTime) {

            #Write-Output "Job $($WebScan_RunningJob.Name) stuck, stopping.."

            $WebLog2 = @{    
                Local_Website     = $WebScan_RunningJob.Name
                HttpStatusCode = "N/A"
                WebScanResult  = "jndi:ldap:// Failed"
                Vulnerable     = $False 
                WebScan_Ports     = ($WebScan_RunningJob.Name -replace "https://127\.0\.0\.1:","") -replace "http://127\.0\.0\.1:",""                             
            }                  

            $TempObj12 = New-Object -TypeName psobject -Property $WebLog2 
            $WebScan_Results += $TempObj12        

            $WebScan_RunningJob | Stop-Job
            #Write-Output "Job $($WebScan_RunningJob.Name) stopped."

        }
    }

    $WebScan_CompletedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })

    Foreach ($WebScan_CompletedJob in $WebScan_CompletedJobs) {   

        #Write-Output "Waiting 5 seconds for Job $($WebScan_CompletedJob.Name) to complete.."
        Start-Sleep -Seconds 5  

        #Write-Output "Scan $($WebScan_CompletedJob.Name) complete."

        $WebScan_ChildJob = $WebScan_CompletedJob.ChildJobs[0]
        $WebScan_ChildJobInfo = $WebScan_ChildJob.Output

        $WebLog2 = @{    
            Local_Website     = $WebScan_CompletedJob.Name
            HttpStatusCode = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { $WebScan_ChildJobInfo.StatusCode }  Else { "N/A" }  
            WebScanResult  = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { "jndi:ldap:// Success" }  Else { "jndi:ldap:// Failed" }  
            Vulnerable     = If (-NOT [string]::IsNullOrEmpty($WebScan_ChildJobInfo.StatusCode)) { $True }  Else { $False }
            WebScan_Ports     = ($WebScan_RunningJob.Name -replace "https://127\.0\.0\.1:","") -replace "http://127\.0\.0\.1:",""                
        }                  

        $TempObj13 = New-Object -TypeName psobject -Property $WebLog2 
        $WebScan_Results += $TempObj13

        $WebScan_CompletedJob | Remove-Job        

        Start-Sleep 5   
                        
    } 

} 
Until ($CountingJobs -eq "0")

#Get-job | Stop-Job
Get-Job | Remove-Job

#Setup all the strings and compress results into 1 line for main report.
$WebScan_Vulnerable = $WebScan_Results | Where-Object {$_.Vulnerable -eq $True}
$WebScan_Ports = $WebScan_Results | Where-Object {$_.Vulnerable -eq $True}
$WebScan_Port = $WebScan_Ports | Select-Object -ExpandProperty WebScan_Ports
$WebScan_Port_String = $WebScan_Port -join ', '

$WebScanResult_String = $WebScan_Vulnerable.WebScanResult[0]

$WebScan_Vulnerable_String = $WebScan_Vulnerable.Vulnerable[0]


$WebScan_httpStatusCodes = $WebScan_Results | Where-Object {$_.Vulnerable -eq $True}
$WebScan_httpStatusCode = $WebScan_httpStatusCodes | Select-Object -ExpandProperty HttpStatusCode
$WebScan_httpStatusCode_String = $WebScan_httpStatusCode -join ', '


$WebScan_Local_Website = $WebScan_Results | Where-Object {$_.Vulnerable -eq $True}
$WebScan_Local_Website1  = $WebScan_Local_Website | Select-Object -ExpandProperty Local_Website
$WebScan_Local_Website_String = $WebScan_Local_Website1 -join ', '

write-Host "13.) Complete."
write-Host "14.) Building Report.."
####
# Web Scanning End
###


$JarProp = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "pom.properties" -or $_.Name -eq "Manifest.mf"  } |  Select-Object Name, FullName
$JndiLookup = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "JndiLookup.class" } |  Select-Object Name, FullName
$ManifestMF = Get-ChildItem -Path "C:\Temp\Log4j\Extracted\" -Recurse -OutBuffer 1000 | Where-Object { $_.Name -eq "Manifest.mf" } |  Select-Object Name, FullName

#Setup Regex for version scraping from pom.properties & Manifest.mf if pom.properties doesn't exit
$regex = "^(version=+[0-9]+[.]+[0-9]+[.]+[0-9])"
$Regex2 = "C:\\Temp\\Log4j\\Extracted\\[0-9]" 
$regex3 = "^(groupId=)"
$regex4 = "^(artifactId=)"
$Regex5 = "^(Manifest-Version:[ ][0-9][.][0-9])"
$Regex6 = "^(Ant-Version:.*)" 
$Regex6_2 = "^(Implementation-Version:.*)"             
$Regex7 = "^(Created-By:.*)"          

$LinkingObject = Import-csv "C:\Temp\Log4j\Extracted\Report.csv"

$ReportObj = @()

Foreach ($PropFile in $JarProp) {

#If .jar files have a pom.properties use it, else use the MANIFEST.MF to try get versioning
$PomPropertiesExist = If ($TestPath = (test-path ($PropFile.FullName -replace "MANIFEST.MF","Pom.properties"))) {$TestPath}

If ($PomPropertiesExist -eq $True) {

 #Added jindi file matching
                            $JindiInPom = ($PropFile.FullName -replace "\\Pom.Properties", "") -replace "\\MANIFEST.MF", ""
                            $JindiMatch = ($JndiLookup.FullName -replace "\\JndiLookup.class", "") -replace "\\MANIFEST.MF", ""

                            If ($JindiInPom -in $JindiMatch) { $Jindi = $True } Else { $Jindi = $False }

                            $DataMatch = $PropFile.FullName | Select-String $Regex2 -AllMatches | ForEach-Object { $_.Matches.Value }
                            $ReferenceNumber = $DataMatch.Substring($DataMatch.Length - 1)

    $Log4JFullPathValue = @()

    $ObjProp1 = @{    
        ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
        FullPath                  = ([String]$Log4JFullPathValue += Foreach ($Number in $LinkingObject) { If ($Number.ReferenceNumber -eq $ReferenceNumber) { $Number.FullPath } })    
        JndiLookupClass           = $Jindi
        Log4JVersion              = (($File = Get-Content $PropFile.FullName) | Select-String -pattern $Regex) -replace "version=", ""
        GroupId                   = ($GroupId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex3")) -replace "groupid=", ""
        artifactId                = ($artifactId = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex4")) -replace "artifactId=", ""
        PomPropertiesExist = $PomPropertiesExist
        Suspected_Processes       = If (-NOT [string]::IsNullOrEmpty($NetworkStats.Process)) { [String]$NetworkStats.Process }  Else { [string]"N/A" } 
        Suspected_Ports           = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalPort)) { [String]$NetworkStats.LocalPort }  Else { [string]"N/A" }
        Suspected_LocalAddresses  = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalAddress)) { [String]$NetworkStats.LocalAddress }  Else { [string]"N/A" }
        PSVersion = ($PSVersionTable.PSVersion)
        Suspected_FullNetworkInfo = If (-NOT [string]::IsNullOrEmpty($NetworkStats)) { $NetworkStats | ConvertTo-Json -Depth 100 -Compress }  Else { [string]"N/A" }
        WebScan_Ports     = If (-NOT [string]::IsNullOrEmpty($WebScan_Port_String)) { [String]$WebScan_Port_String }  Else { [string]"N/A" } 
        WebScan_Result  = If (-NOT [string]::IsNullOrEmpty($WebScanResult_String)) { [String]$WebScanResult_String }  Else { [string]"N/A" }
        WebScan_Vulnerable     = If (-NOT [string]::IsNullOrEmpty($WebScan_Vulnerable_String)) { [String]$WebScan_Vulnerable_String }  Else { [string]"N/A" }
        WebScan_httpStatusCode = If (-NOT [string]::IsNullOrEmpty($WebScan_httpStatusCode_String)) { [String]$WebScan_httpStatusCode_String }  Else { [string]"N/A" }
        WebScan_Local_WebSite = If (-NOT [string]::IsNullOrEmpty($WebScan_Local_Website_String)) { [String]$WebScan_Local_Website_String }  Else { [string]"N/A" } 
    }

    $TempObj = New-Object -TypeName psobject -Property $ObjProp1 
    $ReportObj += $TempObj
    }
    
Else {

$PomPropertiesExist = $False

 #Added jindi file matching
                            $JindiInPom = ($PropFile.FullName -replace "\\Pom.Properties", "") -replace "\\MANIFEST.MF", ""
                            $JindiMatch = ($JndiLookup.FullName -replace "\\JndiLookup.class", "") -replace "\\MANIFEST.MF", ""

                            If ($JindiInPom -in $JindiMatch) { $Jindi = $True } Else { $Jindi = $False }

                            $DataMatch = $PropFile.FullName | Select-String $Regex2 -AllMatches | ForEach-Object { $_.Matches.Value }
                            $ReferenceNumber = $DataMatch.Substring($DataMatch.Length - 1)

    $Log4JFullPathValue = @()

    $ObjProp1 = @{    
        ServerName                = [System.Net.Dns]::GetHostByName($env:computerName).HostName
        FullPath                  = ([String]$Log4JFullPathValue += Foreach ($Number in $LinkingObject) { If ($Number.ReferenceNumber -eq $ReferenceNumber) { $Number.FullPath } })    
        JndiLookupClass           = $Jindi
        Log4JVersion          = "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($MF_ImplementationVersion = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex5"))
        GroupId               =  If (($NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6")).length -eq "0") {"No Pom.Properties File Found, Tried older MANIFEST.MF:" + ( $NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6_2"))} Else {"No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($NoMF = $MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex6"))}
        artifactId            = "No Pom.Properties File Found, Tried older MANIFEST.MF:" + ($MF_ImplementationTitle = ($ObjFile = ($File = Get-Content $PropFile.FullName) | Select-String -Pattern "$Regex7")) #-replace "artifactId=", ""
        PomPropertiesExist = $PomPropertiesExist
        Suspected_Processes       = If (-NOT [string]::IsNullOrEmpty($NetworkStats.Process)) { [String]$NetworkStats.Process }  Else { [string]"N/A" } 
        Suspected_Ports           = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalPort)) { [String]$NetworkStats.LocalPort }  Else { [string]"N/A" }
        Suspected_LocalAddresses  = If (-NOT [string]::IsNullOrEmpty($NetworkStats.LocalAddress)) { [String]$NetworkStats.LocalAddress }  Else { [string]"N/A" }
        PSVersion = ($PSVersionTable.PSVersion)
        Suspected_FullNetworkInfo = If (-NOT [string]::IsNullOrEmpty($NetworkStats)) { $NetworkStats | ConvertTo-Json -Depth 100 -Compress }  Else { [string]"N/A" }
        WebScan_Ports     = If (-NOT [string]::IsNullOrEmpty($WebScan_Port_String)) { [String]$WebScan_Port_String }  Else { [string]"N/A" } 
        WebScan_Result  = If (-NOT [string]::IsNullOrEmpty($WebScanResult_String)) { [String]$WebScanResult_String }  Else { [string]"N/A" }
        WebScan_Vulnerable     = If (-NOT [string]::IsNullOrEmpty($WebScan_Vulnerable_String)) { [String]$WebScan_Vulnerable_String }  Else { [string]"N/A" }
        WebScan_httpStatusCode = If (-NOT [string]::IsNullOrEmpty($WebScan_httpStatusCode_String)) { [String]$WebScan_httpStatusCode_String }  Else { [string]"N/A" }
        WebScan_Local_WebSite = If (-NOT [string]::IsNullOrEmpty($WebScan_Local_Website_String)) { [String]$WebScan_Local_Website_String }  Else { [string]"N/A" } 

    }

    $TempObj = New-Object -TypeName psobject -Property $ObjProp1 
    $ReportObj += $TempObj
    }
    }

   $ReportObj =  $ReportObj | Where-Object {$_.Log4JVersion -ne ""}

$ReportObj3 = @()

Foreach ($Log4jItem in $ReportObj) {

$ObjProp3 = [ordered]@{    
        ServerName                = $Log4jItem.ServerName
        FullPath                  = $Log4jItem.FullPath
        JndiLookupClass           = $Log4jItem.JndiLookupClass
        Log4JVersion              = $Log4jItem.Log4JVersion
        GroupId                   = $Log4jItem.GroupId
        artifactId                = $Log4jItem.artifactId
        PomPropertiesExist = $Log4jItem.PomPropertiesExist
        WebScan_Ports     =         $Log4jItem.WebScan_Ports
        WebScan_Result  = $Log4jItem.WebScan_Result
        WebScan_Vulnerable     = $Log4jItem.WebScan_Vulnerable
        WebScan_httpStatusCode = $Log4jItem.WebScan_httpStatusCode 
        WebScan_Local_WebSite = $Log4jItem.WebScan_Local_WebSite
        Suspected_Processes       = $Log4jItem.Suspected_Processes
        Suspected_Ports           = $Log4jItem.Suspected_Ports
        Suspected_LocalAddresses  = $Log4jItem.Suspected_LocalAddresses
        PSVersion = $Log4jItem.PSVersion
        Suspected_FullNetworkInfo = $Log4jItem.Suspected_FullNetworkInfo
                    
    }
    $TempObj3 = New-Object -TypeName psobject -Property $ObjProp3 
    $ReportObj3 += $TempObj3
}

Write-host "15.) Complete."

$ReportObj3 | Export-csv C:\Temp\Log4j\Log4J-Report-$HostServer.csv -NoTypeInformation -Force

Remove-Item "C:\temp\Log4j\Extracted\" -Recurse
Remove-Item "C:\temp\Log4j\log4j-reports" -Recurse   

Write-host "16.) --All Complete--"
Write-host "17.) ------------------" 
    
