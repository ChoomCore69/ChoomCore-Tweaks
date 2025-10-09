# ChoomCore GUI Application - Windows Optimization Tool (Complete Version)
################################################################
# LICENSED UNDER GPL-3.0
#
# Original Tweak Logic (Core): [ChoomCore]
# GUI Wrapper Development: [LexBoosT]
#
################################################################
Add-Type -MemberDefinition @"
[DllImport("kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
"@ -Name "Win32Console" -Namespace Win32Functions -PassThru | Out-Null

$consolePtr = [Win32Functions.Win32Console]::GetConsoleWindow()
if ($consolePtr -ne [IntPtr]::Zero) {
    [Win32Functions.Win32Console]::ShowWindow($consolePtr, 0) | Out-Null
}

# Suppress all output streams
$null = $host.UI.RawUI.WindowTitle = "ChoomCore GUI - Loading..."
$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

# Load Windows Forms assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

# Data structure for ALL tweaks from ChoomCore_Tweaks.ps1
$tweaksData = @{
    Services = @(
        @{Name = "Connected User Experiences and Telemetry"; Command = "Stop-Service 'Connected User Experiences and Telemetry' -Force; Set-Service 'Connected User Experiences and Telemetry' -StartupType Disabled"; Description = "Disable Microsoft Telemetry"},
        @{Name = "MapsBroker"; Command = "Stop-Service MapsBroker -Force; Set-Service MapsBroker -StartupType Disabled"; Description = "Disable Maps Service"},
        @{Name = "Spooler"; Command = "Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled"; Description = "Disable Print Spooler"},
        @{Name = "DiagTrack"; Command = "Stop-Service DiagTrack -Force; Set-Service DiagTrack -StartupType Disabled"; Description = "Disable Diagnostic Tracking"},
        @{Name = "WerSvc"; Command = "Stop-Service WerSvc -Force; Set-Service WerSvc -StartupType Disabled"; Description = "Disable Error Reporting"},
        @{Name = "DusmSvc"; Command = "Stop-Service DusmSvc -Force; Set-Service DusmSvc -StartupType Disabled"; Description = "Disable Data Usage Service"},
        @{Name = "SCardSvr"; Command = "Stop-Service SCardSvr -Force; Set-Service SCardSvr -StartupType Disabled"; Description = "Disable Smart Card"},
        @{Name = "WbioSrvc"; Command = "Stop-Service WbioSrvc -Force; Set-Service WbioSrvc -StartupType Disabled"; Description = "Disable Windows Biometric"},
        @{Name = "bthserv"; Command = "Stop-Service bthserv -Force; Set-Service bthserv -StartupType Disabled"; Description = "Disable Bluetooth"},
        @{Name = "dmwappushservice"; Command = "Stop-Service dmwappushservice -Force; Set-Service dmwappushservice -StartupType Disabled"; Description = "Disable WAP Push"},
        @{Name = "lfsvc"; Command = "Stop-Service lfsvc -Force; Set-Service lfsvc -StartupType Disabled"; Description = "Disable Geolocation"},
        @{Name = "SensorService"; Command = "Stop-Service SensorService -Force; Set-Service SensorService -StartupType Disabled"; Description = "Disable Sensors"},
        @{Name = "WpnUserService"; Command = "Stop-Service WpnUserService -Force; Set-Service WpnUserService -StartupType Disabled"; Description = "Disable Push Notifications"},
        @{Name = "DiagSvc"; Command = "Stop-Service -Name DiagSvc -Force; Set-Service -Name DiagSvc -StartupType Disabled"; Description = "Disable Diagnostic Service"},
        @{Name = "CDPUserSvc"; Command = "Stop-Service 'CDPUserSvc' -Force; Set-Service 'CDPUserSvc' -StartupType Disabled"; Description = "Disable Connected Device Platform"},
        @{Name = "PcaSvc"; Command = "Stop-Service 'PcaSvc' -Force; Set-Service 'PcaSvc' -StartupType Disabled"; Description = "Disable Program Compatibility Assistant"},
        @{Name = "AppVClient"; Command = "Stop-Service 'AppVClient' -Force; Set-Service 'AppVClient' -StartupType Disabled"; Description = "Disable App-V Client"},
        @{Name = "PhoneSvc"; Command = "Stop-Service PhoneSvc -Force; Set-Service PhoneSvc -StartupType Disabled"; Description = "Disable Phone Service"},
        @{Name = "MessagingService"; Command = "Stop-Service MessagingService -Force; Set-Service MessagingService -StartupType Disabled"; Description = "Disable Messaging Service"},
        @{Name = "SharedAccess"; Command = "Stop-Service SharedAccess -Force; Set-Service SharedAccess -StartupType Disabled"; Description = "Disable Internet Connection Sharing"},
        @{Name = "RetailDemo"; Command = "Stop-Service RetailDemo -Force; Set-Service RetailDemo -StartupType Disabled"; Description = "Disable Retail Demo"},
        @{Name = "RemoteRegistry"; Command = "Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled"; Description = "Disable Remote Registry"},
        @{Name = "SSDPSRV"; Command = "Stop-Service SSDPSRV -Force; Set-Service SSDPSRV -StartupType Disabled"; Description = "Disable SSDP Discovery"},
        @{Name = "upnphost"; Command = "Stop-Service upnphost -Force; Set-Service upnphost -StartupType Disabled"; Description = "Disable UPnP Device Host"},
        @{Name = "iphlpsvc"; Command = "Stop-Service iphlpsvc -Force; Set-Service iphlpsvc -StartupType Disabled"; Description = "Disable IP Helper"},
        @{Name = "EFS"; Command = "Stop-Service -Name 'EFS' -Force; Set-Service -Name 'EFS' -StartupType Disabled"; Description = "Disable Encrypting File System"},
        @{Name = "fdPHost"; Command = "Stop-Service fdPHost -Force; Set-Service fdPHost -StartupType Disabled"; Description = "Disable Function Discovery Provider"},
        @{Name = "FDResPub"; Command = "Stop-Service FDResPub -Force; Set-Service FDResPub -StartupType Disabled"; Description = "Disable Function Discovery Resource"},
        @{Name = "DmEnrollmentSvc"; Command = "Stop-Service -Name 'DmEnrollmentSvc' -Force -ErrorAction SilentlyContinue; Set-Service -Name 'DmEnrollmentSvc' -StartupType Disabled"; Description = "Disable Device Management Enrollment"},
        @{Name = "DeviceAssociationBrokerSvc"; Command = "Stop-Service DeviceAssociationBrokerSvc -Force; Set-Service DeviceAssociationBrokerSvc -StartupType Disabled"; Description = "Disable Device Association Service"},
        @{Name = "cbdhsvc"; Command = "Stop-Service -Name 'cbdhsvc' -Force; Set-Service -Name 'cbdhsvc' -StartupType Disabled"; Description = "Disable Clipboard User Service"},
        @{Name = "UdkUserSvc"; Command = "Stop-Service -Name 'UdkUserSvc' -Force; Set-Service -Name 'UdkUserSvc' -StartupType Disabled"; Description = "Disable UDK User Service"},
        @{Name = "WSAIFabricSvc"; Command = "Stop-Service -Name 'WSAIFabricSvc' -Force; Set-Service -Name 'WSAIFabricSvc' -StartupType Disabled"; Description = "Disable WSL Service"},
        @{Name = "embeddedmode"; Command = "Stop-Service -Name 'embeddedmode' -Force; Set-Service -Name 'embeddedmode' -StartupType Disabled"; Description = "Disable Embedded Mode"},
        @{Name = "icssvc"; Command = "Stop-Service -Name 'icssvc' -Force; Set-Service -Name 'icssvc' -StartupType Disabled"; Description = "Disable Windows Mobile Hotspot"},
        @{Name = "NaturalAuthentication"; Command = "Stop-Service -Name 'NaturalAuthentication' -Force; Set-Service -Name 'NaturalAuthentication' -StartupType Disabled"; Description = "Disable Natural Authentication"},
        @{Name = "HvHost"; Command = "Stop-Service -Name 'HvHost' -Force; Set-Service -Name 'HvHost' -StartupType Disabled"; Description = "Disable HV Host Service"},
        @{Name = "vmickvpexchange"; Command = "Stop-Service -Name 'vmickvpexchange' -Force; Set-Service -Name 'vmickvpexchange' -StartupType Disabled"; Description = "Disable VM IC VSS Exchange"},
        @{Name = "vmicguestinterface"; Command = "Stop-Service -Name 'vmicguestinterface' -Force; Set-Service -Name 'vmicguestinterface' -StartupType Disabled"; Description = "Disable VM IC Guest Interface"},
        @{Name = "WpcMonSvc"; Command = "Stop-Service 'WpcMonSvc' -Force; Set-Service 'WpcMonSvc' -StartupType Disabled"; Description = "Disable Parental Controls"},
        @{Name = "AssignedAccessManagerSvc"; Command = "Stop-Service -Name 'AssignedAccessManagerSvc' -Force; Set-Service -Name 'AssignedAccessManagerSvc' -StartupType Disabled"; Description = "Disable Assigned Access Manager"},
        @{Name = "BluetoothUserService"; Command = "Stop-Service -Name 'BluetoothUserService' -Force; Set-Service -Name 'BluetoothUserService' -StartupType Disabled"; Description = "Disable Bluetooth User Service"},
        @{Name = "CDPSvc"; Command = "Stop-Service -Name 'CDPSvc' -Force; Set-Service -Name 'CDPSvc' -StartupType Disabled"; Description = "Disable Connected Devices Platform"},
        @{Name = "CertPropSvc"; Command = "Stop-Service -Name 'CertPropSvc' -Force; Set-Service -Name 'CertPropSvc' -StartupType Disabled"; Description = "Disable Certificate Propagation"},
        @{Name = "SCPolicySvc"; Command = "Stop-Service -Name 'SCPolicySvc' -Force; Set-Service -Name 'SCPolicySvc' -StartupType Disabled"; Description = "Disable Smart Card Removal Policy"},
        @{Name = "TrkWks"; Command = "Stop-Service -Name 'TrkWks' -Force; Set-Service -Name 'TrkWks' -StartupType Disabled"; Description = "Disable Distributed Link Tracking"},
        @{Name = "Wecsvc"; Command = "Stop-Service -Name 'Wecsvc' -Force; Set-Service -Name 'Wecsvc' -StartupType Disabled"; Description = "Disable Windows Event Collector"},
        @{Name = "WPDBusEnum"; Command = "Stop-Service -Name 'WPDBusEnum' -Force; Set-Service -Name 'WPDBusEnum' -StartupType Disabled"; Description = "Disable Portable Device Enumerator"},
        @{Name = "WpnService"; Command = "Stop-Service -Name 'WpnService' -Force; Set-Service -Name 'WpnService' -StartupType Disabled"; Description = "Disable Windows Push Notifications"},
        @{Name = "WimMount"; Command = "Stop-Service -Name 'WimMount' -Force; Set-Service -Name 'WimMount' -StartupType Disabled"; Description = "Disable Windows Image Mounting"},
        @{Name = "W32Time"; Command = "Stop-Service -Name 'W32Time' -Force; Set-Service -Name 'W32Time' -StartupType Disabled"; Description = "Disable Windows Time"},
        @{Name = "SENS"; Command = "Stop-Service -Name 'SENS' -Force; Set-Service -Name 'SENS' -StartupType Disabled"; Description = "Disable System Event Notification"},
        @{Name = "SstpSvc"; Command = "Stop-Service -Name 'SstpSvc' -Force; Set-Service -Name 'SstpSvc' -StartupType Disabled"; Description = "Disable SSTP Service"},
        @{Name = "pla"; Command = "Stop-Service -Name 'pla' -Force; Set-Service -Name 'pla' -StartupType Disabled"; Description = "Disable Performance Logs & Alerts"},
        @{Name = "SessionEnv"; Command = "Stop-Service -Name 'SessionEnv' -Force; Set-Service -Name 'SessionEnv' -StartupType Disabled"; Description = "Disable Remote Desktop Configuration"},
        @{Name = "PeerDistSvc"; Command = "Stop-Service -Name 'PeerDistSvc' -Force; Set-Service -Name 'PeerDistSvc' -StartupType Disabled"; Description = "Disable BranchCache"},
        @{Name = "Themes"; Command = "Stop-Service -Name 'Themes' -Force; Set-Service -Name 'Themes' -StartupType Disabled"; Description = "Disable Themes"},
        @{Name = "DsSvc"; Command = "Stop-Service -Name 'DsSvc' -Force; Set-Service -Name 'DsSvc' -StartupType Disabled"; Description = "Disable Data Sharing Service"},
        @{Name = "UevAgentService"; Command = "Stop-Service -Name 'UevAgentService' -Force; Set-Service -Name 'UevAgentService' -StartupType Disabled"; Description = "Disable UE-V Agent"},
        @{Name = "QWAVE"; Command = "Stop-Service -Name 'QWAVE' -Force; Set-Service -Name 'QWAVE' -StartupType Disabled"; Description = "Disable Quality Windows Audio Video"},
        @{Name = "SensrSvc"; Command = "Stop-Service -Name 'SensrSvc' -Force; Set-Service -Name 'SensrSvc' -StartupType Disabled"; Description = "Disable Sensor Monitoring"},
        @{Name = "NcdAutoSetup"; Command = "Stop-Service -Name 'NcdAutoSetup' -Force; Set-Service -Name 'NcdAutoSetup' -StartupType Disabled"; Description = "Disable Network Connected Devices Auto-Setup"},
        @{Name = "Wcmsvc"; Command = "Stop-Service -Name 'Wcmsvc' -Force; Set-Service -Name 'Wcmsvc' -StartupType Disabled"; Description = "Disable Windows Connection Manager"},
        @{Name = "WCNCSVC"; Command = "Stop-Service WCNCSVC -Force; Set-Service WCNCSVC -StartupType Disabled"; Description = "Disable Windows Connect Now"},
        @{Name = "WdiServiceHost"; Command = "Stop-Service WdiServiceHost -Force; Set-Service WdiServiceHost -StartupType Disabled"; Description = "Disable Diagnostic Service Host"},
        @{Name = "BTAGService"; Command = "Stop-Service BTAGService -Force; Set-Service BTAGService -StartupType Disabled"; Description = "Disable Bluetooth Audio Gateway"},
        @{Name = "FrameServer"; Command = "Stop-Service FrameServer -Force; Set-Service FrameServer -StartupType Disabled"; Description = "Disable Windows Camera Frame Server"},
        @{Name = "SEMgrSvc"; Command = "Stop-Service SEMgrSvc -Force; Set-Service SEMgrSvc -StartupType Disabled"; Description = "Disable Payments and NFC/SE Manager"},
        @{Name = "PerceptionSimulation"; Command = "Stop-Service PerceptionSimulation -Force; Set-Service PerceptionSimulation -StartupType Disabled"; Description = "Disable Windows Perception Simulation"},
        @{Name = "CaptureService"; Command = "Stop-Service CaptureService -Force; Set-Service CaptureService -StartupType Disabled"; Description = "Disable Windows Capture Service"},
        @{Name = "wisvc"; Command = "Stop-Service wisvc -Force; Set-Service wisvc -StartupType Disabled"; Description = "Disable Windows Insider Service"},
        @{Name = "vmms"; Command = "Stop-Service vmms -Force -ErrorAction SilentlyContinue; Set-Service vmms -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Hyper-V Virtual Machine Management"},
        @{Name = "RemoteAccess"; Command = "Stop-Service RemoteAccess -Force; Set-Service RemoteAccess -StartupType Disabled"; Description = "Disable Routing and Remote Access"},
        @{Name = "RasMan"; Command = "Stop-Service RasMan -Force; Set-Service RasMan -StartupType Disabled"; Description = "Disable Remote Access Connection Manager"},
        @{Name = "lltdsvc"; Command = "Stop-Service lltdsvc -Force; Set-Service lltdsvc -StartupType Disabled"; Description = "Disable Link-Layer Topology Discovery"},
        @{Name = "Netlogon"; Command = "Stop-Service Netlogon -Force -ErrorAction SilentlyContinue; Set-Service Netlogon -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Netlogon"},
        @{Name = "DeviceAssociationService"; Command = "Stop-Service DeviceAssociationService -Force -ErrorAction SilentlyContinue; Set-Service DeviceAssociationService -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Device Association Service"},
        @{Name = "otc"; Command = "Stop-Service otc -Force -ErrorAction SilentlyContinue; Set-Service otc -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Optimal Transfer Client"},
        @{Name = "IKEEXT"; Command = "Stop-Service 'IKEEXT' -Force; Set-Service 'IKEEXT' -StartupType Disabled"; Description = "Disable IKE and AuthIP IPsec Keying"},
        @{Name = "WFDSConMgrSvc"; Command = "Stop-Service 'WFDSConMgrSvc' -Force; Set-Service 'WFDSConMgrSvc' -StartupType Disabled"; Description = "Disable Wi-Fi Direct Services Connection Manager"},
        @{Name = "RpcLocator"; Command = "Stop-Service RpcLocator -Force; Set-Service RpcLocator -StartupType Disabled"; Description = "Disable Remote Procedure Call Locator"},
        @{Name = "BDESVC"; Command = "Stop-Service BDESVC -Force; Set-Service BDESVC -StartupType Disabled; sc delete BDESVC"; Description = "Disable BitLocker Drive Encryption"},
        @{Name = "KtmRm"; Command = "sc.exe config KtmRm start= disabled; Stop-Service KtmRm -Force"; Description = "Disable KTM Resource Manager"},
        @{Name = "SensorDataService"; Command = "Stop-Service SensorDataService -Force; Set-Service SensorDataService -StartupType Disabled"; Description = "Disable Sensor Data Service"},
        @{Name = "SmsRouter"; Command = "Stop-Service SmsRouter -Force; Set-Service SmsRouter -StartupType Disabled"; Description = "Disable Microsoft Windows SMS Router"},
        @{Name = "WiaRpc"; Command = "sc.exe config WiaRpc start= disabled; Stop-Service WiaRpc -Force"; Description = "Disable Still Image Acquisition Events"}
    )
    ScheduledTasks = @(
        @{Name = "XblGameSave Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*XblGameSave*'} | Disable-ScheduledTask"; Description = "Disable Xbox Game Save Tasks"},
        @{Name = "Microsoft Edge Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*MicrosoftEdge*' -or `$_.TaskName -like '*OfficeClickToRun*'} | Disable-ScheduledTask"; Description = "Disable Microsoft Edge Tasks"},
        @{Name = "ProgramDataUpdater"; Command = "schtasks /Change /TN 'Microsoft\Windows\Application Experience\ProgramDataUpdater' /Disable"; Description = "Disable ProgramDataUpdater"},
        @{Name = "Consolidator"; Command = "schtasks /Change /TN 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' /Disable"; Description = "Disable Consolidator"},
        @{Name = "Disk Diagnostic"; Command = "schtasks /Change /TN 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' /Disable"; Description = "Disable Disk Diagnostic"},
        @{Name = "Autochk Proxy"; Command = "schtasks /Change /TN 'Microsoft\Windows\Autochk\Proxy' /Disable"; Description = "Disable Autochk Proxy"},
        @{Name = "UsbCeip"; Command = "Get-ScheduledTask -TaskName 'Consolidator' | Disable-ScheduledTask; Get-ScheduledTask -TaskName 'UsbCeip' | Disable-ScheduledTask"; Description = "Disable USB CEIP Tasks"},
        @{Name = "Application Experience"; Command = "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Application Experience\' | Disable-ScheduledTask"; Description = "Disable Application Experience Tasks"},
        @{Name = "Customer Experience"; Command = "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Customer Experience Improvement Program\' | Disable-ScheduledTask"; Description = "Disable Customer Experience Tasks"},
        @{Name = "Autochk"; Command = "Get-ScheduledTask -TaskPath '\Microsoft\Windows\Autochk\' | Disable-ScheduledTask"; Description = "Disable Autochk Tasks"},
        @{Name = "Diagnosis Scheduled"; Command = "schtasks /Change /TN '\Microsoft\Windows\Diagnosis\Scheduled' /Disable"; Description = "Disable Diagnosis Scheduled"},
        @{Name = "DiskFootprint Diagnostics"; Command = "schtasks /Change /TN '\Microsoft\Windows\DiskFootprint\Diagnostics' /Disable"; Description = "Disable DiskFootprint Diagnostics"},
        @{Name = "Location Notifications"; Command = "schtasks /Change /TN '\Microsoft\Windows\Location\Notifications' /Disable"; Description = "Disable Location Notifications"},
        @{Name = "Location WindowsActionDialog"; Command = "schtasks /Change /TN '\Microsoft\Windows\Location\WindowsActionDialog' /Disable"; Description = "Disable Location WindowsActionDialog"},
        @{Name = "Maps UpdateTask"; Command = "schtasks /Change /TN '\Microsoft\Windows\Maps\MapsUpdateTask' /Disable"; Description = "Disable Maps UpdateTask"},
        @{Name = "MNO Metadata Parser"; Command = "schtasks /Change /TN '\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser' /Disable"; Description = "Disable MNO Metadata Parser"},
        @{Name = "PushToInstall LoginCheck"; Command = "schtasks /Change /TN '\Microsoft\Windows\PushToInstall\LoginCheck' /Disable"; Description = "Disable PushToInstall LoginCheck"},
        @{Name = "PushToInstall Registration"; Command = "schtasks /Change /TN '\Microsoft\Windows\PushToInstall\Registration' /Disable"; Description = "Disable PushToInstall Registration"},
        @{Name = "FamilySafety Monitor"; Command = "schtasks /Change /TN '\Microsoft\Windows\Shell\FamilySafetyMonitor' /Disable"; Description = "Disable FamilySafety Monitor"},
        @{Name = "FamilySafety Refresh"; Command = "schtasks /Change /TN '\Microsoft\Windows\Shell\FamilySafetyRefresh' /Disable"; Description = "Disable FamilySafety Refresh"},
        @{Name = "Application Experience PcaPatchDbTask"; Command = "schtasks /Change /TN '\Microsoft\Windows\Application Experience\PcaPatchDbTask' /Disable"; Description = "Disable PcaPatchDbTask"},
        @{Name = "Customer Experience Consolidator"; Command = "schtasks /Change /TN '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator' /Disable"; Description = "Disable CEIP Consolidator"},
        @{Name = "Customer Experience UsbCeip"; Command = "schtasks /Change /TN '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' /Disable"; Description = "Disable CEIP UsbCeip"},
        @{Name = "DiskDiagnostic DataCollector"; Command = "schtasks /Change /TN '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' /Disable"; Description = "Disable DiskDiagnostic DataCollector"},
        @{Name = "AppReadiness SqmTask"; Command = "schtasks /Change /TN '\Microsoft\Windows\AppReadiness\SqmTask' /Disable"; Description = "Disable AppReadiness SqmTask"},
        @{Name = "AppxDeploymentClient SvcTrigger"; Command = "schtasks /Change /TN '\Microsoft\Windows\AppxDeploymentClient\SvcTrigger' /Disable"; Description = "Disable AppxDeploymentClient SvcTrigger"},
        @{Name = "Defrag ScheduledDefrag"; Command = "schtasks /Change /TN 'Microsoft\Windows\Defrag\ScheduledDefrag' /Disable"; Description = "Disable Scheduled Defrag"},
        @{Name = "UsbTm Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*UsbTm*'} | Disable-ScheduledTask"; Description = "Disable USB Tasks"},
        @{Name = "WaaSMedic Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*WaaSMedic*'} | Disable-ScheduledTask"; Description = "Disable WaaSMedic Tasks"},
        @{Name = "CompatibilityAppraiser"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*CompatibilityAppraiser*'} | Disable-ScheduledTask"; Description = "Disable Compatibility Appraiser"},
        @{Name = "Device Information Device"; Command = "schtasks /Change /TN '\Microsoft\Windows\Device Information\Device' /Disable"; Description = "Disable Device Information Task"}
    )
    Registry = @(
        @{Name = "Disable Telemetry"; Command = "reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v AllowTelemetry /t REG_DWORD /d 0 /f"; Description = "Disable Telemetry"},
        @{Name = "Disable Game DVR"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR' /v 'AppCaptureEnabled' /t REG_DWORD /d 0 /f; reg add 'HKCU\System\GameConfigStore' /v 'GameDVR_Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Game DVR"},
        @{Name = "Disable Start Recommendations"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_Recommendations' /t REG_DWORD /d 0 /f"; Description = "Hide Start Menu Recommendations"},
        @{Name = "Fast Menu Delay"; Command = "reg add 'HKCU\Control Panel\Desktop' /v MenuShowDelay /t REG_SZ /d 0 /f"; Description = "Speed up Menu Display"},
        @{Name = "Disable Feedback"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Feedback' /v DisableFeedbackNotifications /t REG_DWORD /d 1 /f"; Description = "Disable Feedback Notifications"},
        @{Name = "Disable Remote Assistance"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance' /v fAllowToGetHelp /t REG_DWORD /d 0 /f"; Description = "Disable Remote Assistance"},
        @{Name = "Disable RDP"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' /v fDenyTSConnections /t REG_DWORD /d 1 /f"; Description = "Disable Remote Desktop"},
        @{Name = "Disable Start TrackProgs"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Start_TrackProgs /t REG_DWORD /d 0 /f"; Description = "Disable Start Menu Tracking"},
        @{Name = "Disable File Sharing"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network' /v NoFileSharing /t REG_DWORD /d 1 /f"; Description = "Disable File Sharing"},
        @{Name = "Auto End Tasks"; Command = "reg add 'HKCU\Control Panel\Desktop' /v AutoEndTasks /t REG_SZ /d 1 /f"; Description = "Auto End Tasks on Shutdown"},
        @{Name = "Disable Storage Sense"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy' /v 01 /t REG_DWORD /d 0 /f"; Description = "Disable Storage Sense"},
        @{Name = "Disable CEIP"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows' /v CEIPEnable /t REG_DWORD /d 0 /f"; Description = "Disable Customer Experience Improvement"},
        @{Name = "Disable Edge Prelaunch"; Command = "reg add 'HKCU\Software\Microsoft\Edge\Main' /v AllowPrelaunch /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Edge\Main' /v AllowTabPreloading /t REG_DWORD /d 0 /f"; Description = "Disable Edge Prelaunch"},
        @{Name = "Disable Edge New Tab Content"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Edge' /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\Microsoft\Edge' /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f"; Description = "Disable Edge New Tab Content"},
        @{Name = "Disable Edge HubsSidebar"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Edge' /v HubsSidebarEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Edge Hubs Sidebar"},
        @{Name = "Disable Edge Update Tasks"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f"; Description = "Disable Edge Update Shortcuts"},
        @{Name = "Disable Chrome Metrics"; Command = "reg add 'HKCU\Software\Policies\Google\Chrome' /v MetricsReportingEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\Google\Chrome' /v CrashReportingEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Chrome Metrics"},
        @{Name = "Disable Brave Metrics"; Command = "reg add 'HKCU\Software\Policies\BraveSoftware\Brave' /v MetricsReportingEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\BraveSoftware\Brave' /v CrashReportingEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Brave Metrics"},
        @{Name = "Disable Store Background Access"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsStore' /v Disabled /t REG_DWORD /d 1 /f"; Description = "Disable Store Background Access"},
        @{Name = "Disable Push Notifications"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications' /v ToastEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Push Notifications"},
        @{Name = "Remove OneDrive from Startup"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v OneDrive /t REG_SZ /d '' /f"; Description = "Remove OneDrive from Startup"},
        @{Name = "Remove Edge from Startup"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v Edge /t REG_SZ /d '' /f"; Description = "Remove Edge from Startup"},
        @{Name = "Disable Pen Workspace"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace' /v 'PenAndTouch' /t REG_DWORD /d 0 /f"; Description = "Disable Pen Workspace"},
        @{Name = "Set Explorer LaunchTo"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'LaunchTo' /t REG_DWORD /d 1 /f"; Description = "Set Explorer to Launch to This PC"},
        @{Name = "Disable Recent Docs Menu"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'NoRecentDocsMenu' /t REG_DWORD /d 1 /f"; Description = "Disable Recent Documents Menu"},
        @{Name = "Disable Startup Delay"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'StartupDelayInMSec' /t REG_DWORD /d 0 /f"; Description = "Disable Explorer Startup Delay"},
        @{Name = "Always Show Menus"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'AlwaysShowMenus' /t REG_DWORD /d 1 /f"; Description = "Always Show Menus"},
        @{Name = "Disable SIUF"; Command = "reg add 'HKCU\Software\Microsoft\Siuf\Rules' /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Siuf\Rules' /v PeriodInNanoSeconds /t REG_QWORD /d 0 /f"; Description = "Disable Software Inventory Logging"},
        @{Name = "Disable Activity History"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v PublishUserActivities /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v UploadUserActivities /t REG_DWORD /d 0 /f"; Description = "Disable Activity History"},
        @{Name = "Disable ShowRecommendations"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowRecommendations /t REG_DWORD /d 0 /f"; Description = "Disable Show Recommendations"},
        @{Name = "Disable TaskbarDa"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarDa /t REG_DWORD /d 0 /f"; Description = "Disable Taskbar Search Highlights"},
        @{Name = "Disable OneDrive Sync"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f"; Description = "Disable OneDrive File Sync"},
        @{Name = "Disable Touch Devices"; Command = "Get-PnpDevice | Where-Object { `$_.FriendlyName -like '*touch*' -and `$_.Status -eq 'OK' } | Disable-PnpDevice -Confirm:`$false"; Description = "Disable Touch Input Devices"},
        @{Name = "Set DPI Scaling"; Command = "reg add 'HKCU\Control Panel\Desktop' /v LogPixels /t REG_DWORD /d 96 /f; reg add 'HKCU\Control Panel\Desktop' /v Win8DpiScaling /t REG_DWORD /d 0 /f"; Description = "Set DPI Scaling to 100%"},
        @{Name = "Disable Virtualization Security"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"; Description = "Disable Virtualization-Based Security"},
        @{Name = "Disable Folder Info Tips"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v FolderContentsInfoTip /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ShowInfoTip /t REG_DWORD /d 0 /f"; Description = "Disable Folder Info Tips"},
        @{Name = "Disable Action Center"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v ActionCenterEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Action Center"},
        @{Name = "Disable Windows Spotlight"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Windows\CloudContent' /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f"; Description = "Disable Windows Spotlight"},
        @{Name = "Disable Game Bar"; Command = "reg add 'HKCU\Software\Microsoft\GameBar' /v ShowStartupPanel /t REG_DWORD /d 0 /f"; Description = "Disable Game Bar Startup Panel"},
        @{Name = "Fast App Closing"; Command = "reg add 'HKCU\Control Panel\Desktop' /v WaitToKillAppTimeout /t REG_SZ /d '1000' /f; reg add 'HKCU\Control Panel\Desktop' /v HungAppTimeout /t REG_SZ /d '1000' /f"; Description = "Speed up App Closing"},
        @{Name = "Disable TIPC"; Command = "reg add 'HKCU\Software\Microsoft\Input\TIPC' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Text Input Processor"},
        @{Name = "Disable Auto Run"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f"; Description = "Disable Auto Run for All Drives"},
        @{Name = "Delete Typed Paths"; Command = "reg delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' /f"; Description = "Delete Typed Paths History"},
        @{Name = "Delete AeDebug"; Command = "reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug' /f"; Description = "Delete Auto Debugger Settings"},
        @{Name = "Disable News and Interests"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Dsh' /v AllowNewsAndInterests /t REG_DWORD /d 0 /f"; Description = "Disable News and Interests"},
        @{Name = "Disable Windows Chat"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat' /v ChatEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Windows Chat"},
        @{Name = "Disable DiagTrack"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack' /v DiagTrack /t REG_DWORD /d 0 /f"; Description = "Disable DiagTrack"},
        @{Name = "Disable Windows Copilot"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot' /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f"; Description = "Disable Windows Copilot"},
        @{Name = "Disable Taskbar AI"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAi /t REG_DWORD /d 0 /f"; Description = "Disable Taskbar AI"},
        @{Name = "Disable Force V2 Console"; Command = "reg add 'HKCU\Console' /v ForceV2 /t REG_DWORD /d 0 /f"; Description = "Disable Console V2"},
        @{Name = "Disable Global Background Apps"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' /v GlobalUserDisabled /t REG_DWORD /d 1 /f"; Description = "Disable Global Background Apps"},
        @{Name = "Disable Reliability Timestamp"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' /v TimeStampInterval /t REG_DWORD /d 0 /f"; Description = "Disable Reliability Timestamp"},
        @{Name = "Disable Game DVR Policy"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR' /v value /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR' /v AllowGameDVR /t REG_DWORD /d 0 /f"; Description = "Disable Game DVR Policy"},
        @{Name = "Disable Defender BlockAtFirstSeen"; Command = "Set-MpPreference -DisableBlockAtFirstSeen `$true"; Description = "Disable Defender BlockAtFirstSeen"},
        @{Name = "Disable Defender IOAVProtection"; Command = "Set-MpPreference -DisableIOAVProtection `$true"; Description = "Disable Defender IOAV Protection"},
        @{Name = "Disable Defender ScriptScanning"; Command = "Set-MpPreference -DisableScriptScanning `$true"; Description = "Disable Defender Script Scanning"},
        @{Name = "Disable Device Name in Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f"; Description = "Disable Device Name in Telemetry"},
        @{Name = "Disable Feedback Notifications"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f"; Description = "Disable Feedback Notifications"},
        @{Name = "Disable Tablet Tip In-Place"; Command = "reg add 'HKCU\Software\Microsoft\TabletTip\1.7' /v EnableInPlace /t REG_DWORD /d 0 /f"; Description = "Disable Tablet Tip In-Place"},
        @{Name = "Disable Tablet Tip Edge Margin"; Command = "reg add 'HKCU\Software\Microsoft\TabletTip\1.7' /v EdgeTargetMargin /t REG_DWORD /d 0 /f"; Description = "Disable Tablet Tip Edge Margin"},
        @{Name = "Kill TextInputHost"; Command = "taskkill /f /im TextInputHost.exe"; Description = "Kill Text Input Host Process"},
        @{Name = "Disable Input Personalization"; Command = "reg add 'HKCU\Software\Microsoft\InputPersonalization' /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f; reg add 'HKCU\Software\Microsoft\InputPersonalization' /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f"; Description = "Disable Input Personalization"},
        @{Name = "Disable Harvest Contacts"; Command = "reg add 'HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore' /v HarvestContacts /t REG_DWORD /d 0 /f"; Description = "Disable Harvest Contacts"},
        @{Name = "Disable Advertising ID"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Advertising ID"},
        @{Name = "Disable SmartScreen"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v SmartScreenEnabled /t REG_SZ /d 'Off' /f"; Description = "Disable SmartScreen"},
        @{Name = "Disable SmartScreen Policy"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v EnableSmartScreen /t REG_DWORD /d 0 /f"; Description = "Disable SmartScreen Policy"},
        @{Name = "Disable Defender Sample Submission"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' /v SubmitSamplesConsent /t REG_DWORD /d 2 /f"; Description = "Disable Defender Sample Submission"},
        @{Name = "Disable Defender Spynet"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' /v SpynetReporting /t REG_DWORD /d 0 /f"; Description = "Disable Defender Spynet Reporting"},
        @{Name = "Disable AppCompat AIT"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'AITEnable' /t REG_DWORD /d 0 /f"; Description = "Disable AppCompat AIT"},
        @{Name = "Disable AppCompat Inventory"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisableInventory' /t REG_DWORD /d 1 /f"; Description = "Disable AppCompat Inventory"},
        @{Name = "Disable App Privacy Account Info"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessAccountInfo' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Account Info"},
        @{Name = "Disable App Privacy Call History"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessCallHistory' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Call History"},
        @{Name = "Disable Sync Provider Notifications"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowSyncProviderNotifications' /t REG_DWORD /d 0 /f"; Description = "Disable Sync Provider Notifications"},
        @{Name = "Disable Soft Landing"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableSoftLanding' /t REG_DWORD /d 1 /f"; Description = "Disable Soft Landing"},
        @{Name = "Disable USB Selective Suspend"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\USB\Parameters' /v DisableSelectiveSuspend /t REG_DWORD /d 1 /f"; Description = "Disable USB Selective Suspend"},
        @{Name = "Disable Serialize Startup"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' /v StartupDelayInMSec /t REG_DWORD /d 0 /f"; Description = "Disable Serialize Startup Delay"},
        @{Name = "Disable PCA"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v DisablePCA /t REG_DWORD /d 1 /f"; Description = "Disable Program Compatibility Assistant"},
        @{Name = "Disable Game DVR FSE"; Command = "reg add 'HKCU\System\GameConfigStore' /v 'GameDVR_FSEBehaviorMode' /t REG_DWORD /d 2 /f"; Description = "Disable Game DVR FSE Behavior"},
        @{Name = "Disable CDP Session Authz"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP' /v 'CdpSessionUserAuthzPolicy' /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CDP' /v 'CdpSessionUserAuthzPolicy' /t REG_DWORD /d 0 /f"; Description = "Disable CDP Session User Authz"},
        @{Name = "Disable PLA Operational"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Operational' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable PLA Operational Events"},
        @{Name = "Disable Device Management Events"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Device Management Events"},
        @{Name = "Disable Consumer Features"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f"; Description = "Disable Windows Consumer Features"},
        @{Name = "Disable Clipboard History"; Command = "reg add 'HKCU\Software\Microsoft\Clipboard' /v EnableClipboardHistory /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Clipboard' /v EnableCloudClipboard /t REG_DWORD /d 0 /f"; Description = "Disable Clipboard History"},
        @{Name = "Disable File History"; Command = "reg add 'HKLM\Software\Policies\Microsoft\Windows\FileHistory' /v Disabled /t REG_DWORD /d 1 /f"; Description = "Disable File History"},
        @{Name = "Disable AppCompat AIT Enable"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v AITEnable /t REG_DWORD /d 0 /f"; Description = "Disable AppCompat AIT Enable"},
        @{Name = "Disable Snap Assist"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v SnapAssist /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v SnapFlyoutSuggest /t REG_DWORD /d 0 /f"; Description = "Disable Snap Assist"},
        @{Name = "Disable Start Recommendations"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Start_Recommendations /t REG_DWORD /d 0 /f"; Description = "Disable Start Recommendations"},
        @{Name = "Disable Taskbar Da"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarDa /t REG_DWORD /d 0 /f"; Description = "Disable Taskbar Da"},
        @{Name = "Disable Feeds Taskbar View"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds' /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f"; Description = "Disable Feeds Taskbar View"},
        @{Name = "Disable Narrator Hotkey"; Command = "reg add 'HKCU\Software\Microsoft\Narrator' /v 'UserPrefNarratorHotkey' /t REG_DWORD /d 0 /f"; Description = "Disable Narrator Hotkey"},
        @{Name = "Disable Narrator Startup"; Command = "reg add 'HKCU\Software\Microsoft\Narrator' /v 'UserPrefStartNarratorOnStartup' /t REG_DWORD /d 0 /f"; Description = "Disable Narrator Startup"},
        @{Name = "Disable Narrator WinEnter"; Command = "reg add 'HKCU\Software\Microsoft\Narrator' /v 'WinEnterLaunchEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Narrator WinEnter"},
        @{Name = "Disable Accessibility Configuration"; Command = "reg add 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility' /v Configuration /t REG_SZ /d '' /f"; Description = "Disable Accessibility Configuration"},
        @{Name = "Disable Accessibility Debug"; Command = "reg add 'HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility' /v DebugOutput /t REG_DWORD /d 0 /f"; Description = "Disable Accessibility Debug"},
        @{Name = "Disable Live Captions"; Command = "reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsEnabled' /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsOnboardingComplete' /t REG_DWORD /d 1 /f"; Description = "Disable Live Captions"},
        @{Name = "Disable Toast Notifications"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f"; Description = "Disable Toast Notifications"},
        @{Name = "Disable Location Access"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' /v Value /t REG_SZ /d Deny /f"; Description = "Disable Location Access"},
        @{Name = "Disable Biometrics"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics' /v Enabled /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Biometrics"},
        @{Name = "Disable Vsmlaunchtype"; Command = "bcdedit /set vsmlaunchtype Off"; Description = "Disable VSM Launch Type"},
        @{Name = "Disable DCOM"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Ole' /v EnableDCOM /t REG_SZ /d 'N' /f; reg add 'HKLM\SOFTWARE\Microsoft\Rpc' /v DCOMProtocol /t REG_MULTI_SZ /d '' /f"; Description = "Disable DCOM"},
        @{Name = "Disable Audit Policy"; Command = "auditpol /set /category:* /success:disable /failure:disable"; Description = "Disable Audit Policy"},
        @{Name = "Disable Windows Backup"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsBackup' /v DisableBackup /t REG_DWORD /d 1 /f"; Description = "Disable Windows Backup"},
        @{Name = "Disable Class Store"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\COM3' /v DisableClassStore /t REG_DWORD /d 1 /f"; Description = "Disable Class Store"},
        @{Name = "Disable NTFS Compression"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisableCompression /t REG_DWORD /d 1 /f"; Description = "Disable NTFS Compression"},
        @{Name = "Disable CldFlt"; Command = "cmd /c 'sc config CldFlt start=disabled'"; Description = "Disable Cloud Files Filter"},
        @{Name = "Disable Storqosflt"; Command = "sc.exe config storqosflt start=disabled"; Description = "Disable Storage QoS Filter"},
        @{Name = "Disable WpnUserService Start"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService' /v Start /t REG_DWORD /d 4 /f"; Description = "Disable WpnUserService Start"},
        @{Name = "Disable SMB Device"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' /v SMBDeviceEnabled /t REG_DWORD /d 0 /f"; Description = "Disable SMB Device Enabled"},
        @{Name = "Disable Device Metadata Network"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f"; Description = "Disable Device Metadata from Network"},
        @{Name = "Disable Lfsvc Trigger"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo' /v Start /t REG_DWORD /d 4 /f"; Description = "Disable Geolocation Service Trigger"},
        @{Name = "Disable Alternate Shell"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot' /v 'AlternateShell' /t REG_SZ /d 'cmd.exe' /f"; Description = "Set Alternate Shell to cmd.exe"},
        @{Name = "Disable Apps Access Contacts"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessContacts' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Contacts"},
        @{Name = "Disable Apps Access Email"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessEmail' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Email"},
        @{Name = "Disable Apps Access Messaging"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessMessaging' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Messaging"},
        @{Name = "Disable No Process Contents"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoProcessContents' /t REG_DWORD /d 1 /f"; Description = "Disable Process Contents"},
        @{Name = "Disable DotNet Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework' /v 'DotNetTelemetryOff' /t REG_DWORD /d 1 /f"; Description = "Disable .NET Framework Telemetry"},
        @{Name = "Disable Multicast"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v 'EnableMulticast' /t REG_DWORD /d 0 /f"; Description = "Disable DNS Multicast"},
        @{Name = "Disable Domain Creds"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'DisableDomainCreds' /t REG_DWORD /d 1 /f"; Description = "Disable Domain Credentials"},
        @{Name = "Disable Cross Device Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'AllowCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cross Device Clipboard"},
        @{Name = "Disable Location Sensors"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableLocation' /t REG_DWORD /d 1 /f"; Description = "Disable Location and Sensors"},
        @{Name = "Disable Listview Effects"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewAlphaSelect' /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewShadow' /t REG_DWORD /d 0 /f"; Description = "Disable Listview Effects"},
        @{Name = "Enable Show Comp Color"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCompColor' /t REG_DWORD /d 1 /f"; Description = "Enable Show Compressed Color"},
        @{Name = "Disable Performance Diagnostics"; Command = "wevtutil sl Microsoft-Windows-Diagnostics-Performance/Operational /e:false"; Description = "Disable Performance Diagnostics Events"},
        @{Name = "Disable Start Track Progs"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_TrackProgs' /t REG_DWORD /d 0 /f"; Description = "Disable Start Track Programs"},
        @{Name = "Disable Cross Device Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'EnableCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cross Device Clipboard"},
        @{Name = "Disable Narrator Live Captions"; Command = "reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsLanguage' /t REG_SZ /d '' /f"; Description = "Disable Live Captions Language"},
        @{Name = "Disable Advertising Info"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0 -Force"; Description = "Disable Advertising Info"},
        @{Name = "Disable Tailored Experiences"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesEnabled' -Value 0 -Force"; Description = "Disable Tailored Experiences"},
        @{Name = "Disable Allow Telemetry"; Command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force"; Description = "Disable Allow Telemetry"},
        @{Name = "Disable Device Sync"; Command = "Set-Service -Name 'DeviceSync' -StartupType Disabled -Status Stopped"; Description = "Disable Device Sync Service"},
        @{Name = "Set Network Category Private"; Command = "Set-NetConnectionProfile -NetworkCategory Private"; Description = "Set Network Category to Private"},
        @{Name = "Disable TermService"; Command = "Stop-Service TermService -Force -ErrorAction SilentlyContinue; Set-Service TermService -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Terminal Services"},
        @{Name = "Disable Napagent"; Command = "Stop-Service napagent -Force -ErrorAction SilentlyContinue; Set-Service napagent -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Network Access Protection"},
        @{Name = "Disable Show Info Tip"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowInfoTip' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Show Info Tip"},
        @{Name = "Disable Ncd Auto Flow"; Command = "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name 'NcdAutoFlow' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Ncd Auto Flow"},
        @{Name = "Disable Activities History"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\History' -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Activities History"},
        @{Name = "Disable Activities Roamed"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\RoamedHistory' -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Activities Roamed History"},
        @{Name = "Disable Windows Error Reporting"; Command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue"; Description = "Disable Windows Error Reporting"},
        @{Name = "Disable Windows Error Reporting 2"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting' /v Disabled /t REG_DWORD /d 1 /f"; Description = "Disable Windows Error Reporting"},
        @{Name = "Disable PowerShell Telemetry"; Command = "[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'User')"; Description = "Disable PowerShell Telemetry"},
        @{Name = "Disable Feature Settings Override"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverride /t REG_DWORD /d 3 /f; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f"; Description = "Disable Feature Settings Override"},
        @{Name = "Disable SvcHost Split"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\SvcHost' /v SvcHostSplitThresholdInBytes /t REG_DWORD /d 1 /f"; Description = "Disable SvcHost Split Threshold"},
        @{Name = "Disable 8dot3 Name Creation"; Command = "fsutil 8dot3name set 1"; Description = "Disable 8.3 Name Creation"},
        @{Name = "Disable SENS"; Command = "Stop-Service -Name 'SENS' -Force; Set-Service -Name 'SENS' -StartupType Disabled"; Description = "Disable System Event Notification"},
        @{Name = "Disable Win32 Priority Separation"; Command = "reg add 'HKCU\Control Panel\PriorityControl' /v Win32PrioritySeparation /t REG_DWORD /d 2 /f"; Description = "Set Win32 Priority Separation"},
        @{Name = "Disable Legacy Print Notify"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Printing' /v 'EnableLegacyPrtNotify' /t REG_DWORD /d 0 /f"; Description = "Disable Legacy Print Notify"},
        @{Name = "Disable WSL"; Command = "dism.exe /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux /NoRestart"; Description = "Disable Windows Subsystem for Linux"},
        @{Name = "Disable No Process Contents"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoProcessContents' /t REG_DWORD /d 1 /f"; Description = "Disable Process Contents"},
        @{Name = "Disable DotNet Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework' /v 'DotNetTelemetryOff' /t REG_DWORD /d 1 /f"; Description = "Disable .NET Framework Telemetry"},
        @{Name = "Disable Feedback Notifications"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'DoNotShowFeedbackNotifications' /t REG_DWORD /d 1 /f"; Description = "Disable Feedback Notifications"},
        @{Name = "Disable DNS Multicast"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v 'EnableMulticast' /t REG_DWORD /d 0 /f"; Description = "Disable DNS Multicast"},
        @{Name = "Disable Domain Creds"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'DisableDomainCreds' /t REG_DWORD /d 1 /f"; Description = "Disable Domain Credentials"},
        @{Name = "Disable Input Cross Device"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'AllowCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cross Device Clipboard"},
        @{Name = "Disable Location Sensors"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableLocation' /t REG_DWORD /d 1 /f"; Description = "Disable Location and Sensors"},
        @{Name = "Disable Listview Alpha"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewAlphaSelect' /t REG_DWORD /d 0 /f"; Description = "Disable Listview Alpha Select"},
        @{Name = "Disable Listview Shadow"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewShadow' /t REG_DWORD /d 0 /f"; Description = "Disable Listview Shadow"},
        @{Name = "Enable Show Comp Color"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCompColor' /t REG_DWORD /d 1 /f"; Description = "Enable Show Compressed Color"},
        @{Name = "Disable Performance Events"; Command = "wevtutil sl Microsoft-Windows-Diagnostics-Performance/Operational /e:false"; Description = "Disable Performance Diagnostics Events"},
        @{Name = "Disable Start Track Progs"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_TrackProgs' /t REG_DWORD /d 0 /f"; Description = "Disable Start Track Programs"},
        @{Name = "Disable Input Cross Device"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'EnableCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cross Device Clipboard"},
        @{Name = "Disable Hyper-V Management"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Management-Clients /NoRestart"; Description = "Disable Hyper-V Management Clients"},
        @{Name = "Disable Device Information"; Command = "schtasks /Change /TN '\Microsoft\Windows\Device Information\Device' /Disable"; Description = "Disable Device Information Task"},
        @{Name = "Disable IIS ASPNET45"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ASPNET45 /NoRestart"; Description = "Disable IIS ASP.NET 4.5"},
        @{Name = "Disable IIS Application Init"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ApplicationInit /NoRestart"; Description = "Disable IIS Application Init"},
        @{Name = "Disable IIS Web Management"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebServerManagementTools /NoRestart"; Description = "Disable IIS Web Server Management Tools"},
        @{Name = "Disable MSMQ DCOM"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-DCOMProxy /NoRestart"; Description = "Disable MSMQ DCOM Proxy"},
        @{Name = "Disable MSMQ HTTP"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-HTTP /NoRestart"; Description = "Disable MSMQ HTTP Support"},
        @{Name = "Disable MSMQ Multicast"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-Multicast /NoRestart"; Description = "Disable MSMQ Multicast Support"},
        @{Name = "Disable Apps Access Calendar"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessCalendar' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Calendar"},
        @{Name = "Disable Enhanced Diagnostic"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'LimitEnhancedDiagnosticDataWindowsAnalytics' /t REG_DWORD /d 0 /f"; Description = "Disable Enhanced Diagnostic Data"},
        @{Name = "Disable Device Name Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowDeviceNameInTelemetry' /t REG_DWORD /d 0 /f"; Description = "Disable Device Name in Telemetry"},
        @{Name = "Disable Limit Enhanced Diagnostic"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f"; Description = "Disable Limit Enhanced Diagnostic"},
        @{Name = "Disable Auto Share Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v AutoShareServer /t REG_DWORD /d 0 /f"; Description = "Disable Auto Share Server"},
        @{Name = "Disable Auto Share Wks"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v AutoShareWks /t REG_DWORD /d 0 /f"; Description = "Disable Auto Share Workstation"},
        @{Name = "Disable PCT 1.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable PCT 1.0 Server"},
        @{Name = "Disable SSL 2.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable SSL 2.0 Server"},
        @{Name = "Disable SSL 3.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable SSL 3.0 Server"},
        @{Name = "Disable Automatic Restart SignOn"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f"; Description = "Disable Automatic Restart Sign-On"},
        @{Name = "Disable Shutdown Reason On"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' /v ShutdownReasonOn /t REG_DWORD /d 0 /f"; Description = "Disable Shutdown Reason On"},
        @{Name = "Disable Shutdown Reason UI"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' /v ShutdownReasonUI /t REG_DWORD /d 0 /f"; Description = "Disable Shutdown Reason UI"},
        @{Name = "Disable Component Cleanup"; Command = "dism /online /Cleanup-Image /StartComponentCleanup /NoRestart"; Description = "Disable Component Cleanup"},
        @{Name = "Disable Setting Sync Personalization"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization' /v 'Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Setting Sync Personalization"},
        @{Name = "Disable Setting Sync Theme"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Theme' /v 'Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Setting Sync Theme"},
        @{Name = "Disable Shared Experiences"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WorkplaceJoin' /v 'EnableSharedExperiences' /t REG_DWORD /d 0 /f"; Description = "Disable Shared Experiences"},
        @{Name = "Disable Cloud Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Clipboard' /v 'EnableCloudClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cloud Clipboard"},
        @{Name = "Disable SmartScreen"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' /v 'EnableSmartScreen' /t REG_DWORD /d 0 /f"; Description = "Disable SmartScreen"},
        @{Name = "Disable Startup Delay"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'StartupDelayInMSec' /t REG_DWORD /d 0 /f"; Description = "Disable Startup Delay"},
        @{Name = "Disable Narrator Sound Sentry"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility' /v SoundSentryFlags /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility' /v SoundSentryAnimation /t REG_DWORD /d 0 /f"; Description = "Disable Narrator Sound Sentry"},
        @{Name = "Disable Accessibility Apps"; Command = "Get-AppxPackage *Accessibility* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*Accessibility*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Accessibility Apps"},
        @{Name = "Disable Live Captions Enabled"; Command = "reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Live Captions"},
        @{Name = "Disable Live Captions Onboarding"; Command = "reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsOnboardingComplete' /t REG_DWORD /d 1 /f"; Description = "Disable Live Captions Onboarding"},
        @{Name = "Disable Live Captions Language"; Command = "reg add 'HKCU\Software\Microsoft\Accessibility' /v 'LiveCaptionsLanguage' /t REG_SZ /d '' /f"; Description = "Disable Live Captions Language"},
        @{Name = "Disable Global Toasts"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f"; Description = "Disable Global Toast Notifications"},
        @{Name = "Disable Location Consent"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' /v Value /t REG_SZ /d Deny /f"; Description = "Disable Location Consent"},
        @{Name = "Disable Biometrics Enabled"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Biometrics"},
        @{Name = "Disable Facial Features"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Facial Features"},
        @{Name = "Delete Diagtrack Listener"; Command = "logman delete trace 'Diagtrack-Listener'"; Description = "Delete Diagtrack Listener Trace"},
        @{Name = "Disable VSM Launch Type"; Command = "bcdedit /set vsmlaunchtype Off"; Description = "Disable VSM Launch Type"},
        @{Name = "Disable Rpc Locator"; Command = "Stop-Service RpcLocator -Force; Set-Service RpcLocator -StartupType Disabled"; Description = "Disable RPC Locator"},
        @{Name = "Disable DCOM Enable"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Ole' /v EnableDCOM /t REG_SZ /d 'N' /f"; Description = "Disable DCOM"},
        @{Name = "Disable DCOM Protocol"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Rpc' /v DCOMProtocol /t REG_MULTI_SZ /d '' /f"; Description = "Disable DCOM Protocol"},
        @{Name = "Disable Audit Policy All"; Command = "auditpol /set /category:* /success:disable /failure:disable"; Description = "Disable All Audit Policies"},
        @{Name = "Disable Windows Backup Policy"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\WindowsBackup' /v DisableBackup /t REG_DWORD /d 1 /f"; Description = "Disable Windows Backup"},
        @{Name = "Disable BitLocker"; Command = "Stop-Service BDESVC -Force; Set-Service BDESVC -StartupType Disabled; sc delete BDESVC"; Description = "Disable BitLocker Drive Encryption"},
        @{Name = "Disable COM3 Class Store"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\COM3' /v DisableClassStore /t REG_DWORD /d 1 /f"; Description = "Disable COM3 Class Store"},
        @{Name = "Disable KTM RM"; Command = "sc.exe config KtmRm start= disabled; Stop-Service KtmRm -Force"; Description = "Disable KTM Resource Manager"},
        @{Name = "Disable NTFS Compression"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisableCompression /t REG_DWORD /d 1 /f"; Description = "Disable NTFS Compression"},
        @{Name = "Disable Sensor Data"; Command = "Stop-Service SensorDataService -Force; Set-Service SensorDataService -StartupType Disabled"; Description = "Disable Sensor Data Service"},
        @{Name = "Disable SMS Router"; Command = "Stop-Service SmsRouter -Force; Set-Service SmsRouter -StartupType Disabled"; Description = "Disable SMS Router Service"},
        @{Name = "Disable CldFlt"; Command = "cmd /c 'sc config CldFlt start=disabled'"; Description = "Disable Cloud Files Filter"},
        @{Name = "Disable Storqosflt"; Command = "sc.exe config storqosflt start=disabled"; Description = "Disable Storage QoS Filter"},
        @{Name = "Disable WpnUserService"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService' /v Start /t REG_DWORD /d 4 /f"; Description = "Disable WpnUserService"},
        @{Name = "Disable WiaRpc"; Command = "sc.exe config WiaRpc start= disabled; Stop-Service WiaRpc -Force"; Description = "Disable WIA RPC"},
        @{Name = "Disable SMB Device Enabled"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' /v SMBDeviceEnabled /t REG_DWORD /d 0 /f"; Description = "Disable SMB Device Enabled"},
        @{Name = "Disable Device Metadata"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata' /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f"; Description = "Disable Device Metadata from Network"},
        @{Name = "Disable Lfsvc Trigger Info"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo' /v Start /t REG_DWORD /d 4 /f"; Description = "Disable Geolocation Trigger Info"},
        @{Name = "Disable WSL Feature"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'Microsoft-Windows-Subsystem-Linux' -NoRestart"; Description = "Disable Windows Subsystem for Linux"},
        @{Name = "Disable Printing PDF"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'Printing-PrintToPDFServices-Features' -NoRestart"; Description = "Disable Printing to PDF"},
        @{Name = "Disable PowerShell V2"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2' -NoRestart"; Description = "Disable PowerShell V2"},
        @{Name = "Disable Work Folders"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'WorkFolders-Client' -NoRestart"; Description = "Disable Work Folders Client"},
        @{Name = "Disable Alternate Shell"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot' /v 'AlternateShell' /t REG_SZ /d 'cmd.exe' /f"; Description = "Set Alternate Shell"},
        @{Name = "Disable Apps Access Contacts"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessContacts' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Contacts"},
        @{Name = "Disable Apps Access Email"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessEmail' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Email"},
        @{Name = "Disable Apps Access Messaging"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessMessaging' /t REG_DWORD /d 2 /f"; Description = "Disable Apps Access to Messaging"},
        @{Name = "Disable Legacy Components"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'LegacyComponents' -NoRestart"; Description = "Disable Legacy Components"},
        @{Name = "Disable PowerShell V2 Root"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart"; Description = "Disable PowerShell V2 Root"},
        @{Name = "Disable MSRDC Infrastructure"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'MSRDC-Infrastructure' -NoRestart"; Description = "Disable MSRDC Infrastructure"},
        @{Name = "Disable Printing Foundation"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'Printing-Foundation-Features' -NoRestart"; Description = "Disable Printing Foundation Features"},
        @{Name = "Disable Printing Internet Client"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'Printing-Foundation-InternetPrinting-Client' -NoRestart"; Description = "Disable Printing Internet Client"},
        @{Name = "Disable Ntfs Last Access"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f"; Description = "Disable NTFS Last Access Update"},
        @{Name = "Disable Ntfs 8dot3"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f"; Description = "Disable NTFS 8.3 Name Creation"},
        @{Name = "Disable Device Guard Security"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'EnableVirtualizationBasedSecurity' /t REG_DWORD /d 0 /f"; Description = "Disable Device Guard Security"},
        @{Name = "Disable Device Guard Features"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'RequirePlatformSecurityFeatures' /t REG_DWORD /d 0 /f"; Description = "Disable Device Guard Features"},
        @{Name = "Disable Auto Tray"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'EnableAutoTray' /t REG_DWORD /d 0 /f"; Description = "Disable Auto Tray"},
        @{Name = "Disable Game Bar"; Command = "reg add 'HKCU\Software\Microsoft\GameBar' /v 'AllowGameBar' /t REG_DWORD /d 0 /f"; Description = "Disable Game Bar"},
        @{Name = "Remove HEIF Extension"; Command = "Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage"; Description = "Remove HEIF Image Extension"},
        @{Name = "Remove VP9 Extension"; Command = "Get-AppxPackage *Microsoft.VP9VideoExtensions* | Remove-AppxPackage"; Description = "Remove VP9 Video Extensions"},
        @{Name = "Remove Web Media Extensions"; Command = "Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage"; Description = "Remove Web Media Extensions"},
        @{Name = "Remove Webp Extension"; Command = "Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage"; Description = "Remove WebP Image Extension"},
        @{Name = "Remove Paint App"; Command = "Get-AppxPackage *Microsoft.Paint* | Remove-AppxPackage"; Description = "Remove Paint App"},
        @{Name = "Remove Xbox TCUI"; Command = "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"; Description = "Remove Xbox TCUI"},
        @{Name = "Disable Show Recommendations"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowRecommendations' /t REG_DWORD /d 0 /f"; Description = "Disable Show Recommendations"},
        @{Name = "Disable Activity Feed"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t REG_DWORD /d 0 /f"; Description = "Disable Activity Feed"},
        @{Name = "Disable Printing Internet Client"; Command = "dism /online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client /NoRestart"; Description = "Disable Printing Internet Client"},
        @{Name = "Disable WCF HTTP Activation"; Command = "dism /online /Disable-Feature /FeatureName:WCF-HTTP-Activation /NoRestart"; Description = "Disable WCF HTTP Activation"},
        @{Name = "Disable WCF NonHTTP Activation"; Command = "dism /online /Disable-Feature /FeatureName:WCF-NonHTTP-Activation /NoRestart"; Description = "Disable WCF Non-HTTP Activation"},
        @{Name = "Disable Auto Search"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v AutoSearch /t REG_DWORD /d 0 /f"; Description = "Disable Auto Search"},
        @{Name = "Disable Search Box Suggestions"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f"; Description = "Disable Search Box Suggestions"},
        @{Name = "Disable Remote Access"; Command = "Stop-Service RemoteAccess -Force; Set-Service RemoteAccess -StartupType Disabled"; Description = "Disable Remote Access"},
        @{Name = "Disable Remote Access Connection"; Command = "Stop-Service RasMan -Force; Set-Service RasMan -StartupType Disabled"; Description = "Disable Remote Access Connection Manager"},
        @{Name = "Disable Game Bar Allow"; Command = "reg add 'HKCU\Software\Microsoft\GameBar' /v AllowGameBar /t REG_DWORD /d 0 /f"; Description = "Disable Game Bar Allow"},
        @{Name = "Disable Lock Screen Content"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Rotating Lock Screen"},
        @{Name = "Disable Silent Installed Apps"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Silent Installed Apps"},
        @{Name = "Disable Subscribed Content 338387"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Subscribed Content 338387"},
        @{Name = "Disable Subscribed Content 338388"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Subscribed Content 338388"},
        @{Name = "Disable Subscribed Content 338389"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Subscribed Content 338389"},
        @{Name = "Disable Content Delivery"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f"; Description = "Disable Content Delivery"},
        @{Name = "Disable Apps Sync Devices"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v LetAppsSyncWithDevices /t REG_DWORD /d 2 /f"; Description = "Disable Apps Sync with Devices"},
        @{Name = "Remove Zune Video"; Command = "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*Microsoft.ZuneVideo*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Zune Video"},
        @{Name = "Disable Link Layer Discovery"; Command = "Stop-Service lltdsvc -Force; Set-Service lltdsvc -StartupType Disabled"; Description = "Disable Link-Layer Topology Discovery"},
        @{Name = "Disable Windows Error Reporting"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting' /v Disabled /t REG_DWORD /d 1 /f"; Description = "Disable Windows Error Reporting"},
        @{Name = "Disable Virtual Machine Platform"; Command = "dism /Online /Disable-Feature /FeatureName:VirtualMachinePlatform /NoRestart"; Description = "Disable Virtual Machine Platform"},
        @{Name = "Disable Hypervisor Platform"; Command = "dism /Online /Disable-Feature /FeatureName:HypervisorPlatform /NoRestart"; Description = "Disable Hypervisor Platform"},
        @{Name = "Disable Last Access Update"; Command = "fsutil behavior set disablelastaccess 1"; Description = "Disable Last Access Update"},
        @{Name = "Disable Voice Access"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility\Configuration\VoiceAccess' /v 'Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Voice Access"},
        @{Name = "Disable Search Highlights"; Command = "reg add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings\SearchHighlights' /v 'IsOn' /t REG_DWORD /d 0 /f"; Description = "Disable Search Highlights"},
        @{Name = "Disable Hyper-V Virtual Machine"; Command = "Stop-Service vmms -Force -ErrorAction SilentlyContinue; Set-Service vmms -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Hyper-V Virtual Machine Management"},
        @{Name = "Disable SMB1 Protocol"; Command = "dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart"; Description = "Disable SMB1 Protocol"},
        @{Name = "Disable Telnet Client"; Command = "dism /online /Disable-Feature /FeatureName:TelnetClient /NoRestart"; Description = "Disable Telnet Client"},
        @{Name = "Disable SmbDirect"; Command = "dism /online /Disable-Feature /FeatureName:SmbDirect /NoRestart"; Description = "Disable SMB Direct"},
        @{Name = "Disable WCF TCP PortSharing"; Command = "dism /online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /NoRestart"; Description = "Disable WCF TCP Port Sharing"},
        @{Name = "Disable WCF Services45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-Services45 /NoRestart"; Description = "Disable WCF Services 4.5"},
        @{Name = "Remove Widgets Platform Runtime"; Command = "Get-AppxPackage *Microsoft.WidgetsPlatformRuntime* | Remove-AppxPackage"; Description = "Remove Widgets Platform Runtime"},
        @{Name = "Remove Raw Image Extension"; Command = "Get-AppxPackage *Microsoft.RawImageExtension* | Remove-AppxPackage"; Description = "Remove Raw Image Extension"},
        @{Name = "Remove AVC Encoder"; Command = "Get-AppxPackage *Microsoft.AVCEncoderVideoExtension* | Remove-AppxPackage"; Description = "Remove AVC Encoder Video Extension"},
        @{Name = "Remove HEVC Video Extension"; Command = "Get-AppxPackage *Microsoft.HEVCVideoExtension* | Remove-AppxPackage"; Description = "Remove HEVC Video Extension"},
        @{Name = "Remove MPEG2 Video Extension"; Command = "Get-AppxPackage *Microsoft.MPEG2VideoExtension* | Remove-AppxPackage"; Description = "Remove MPEG2 Video Extension"},
        @{Name = "Disable Advertising Info"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name 'Enabled' -Value 0 -Force"; Description = "Disable Advertising Info"},
        @{Name = "Disable Tailored Experiences"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesEnabled' -Value 0 -Force"; Description = "Disable Tailored Experiences"},
        @{Name = "Disable Allow Telemetry"; Command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Force"; Description = "Disable Allow Telemetry"},
        @{Name = "Disable Device Sync Service"; Command = "Set-Service -Name 'DeviceSync' -StartupType Disabled -Status Stopped"; Description = "Disable Device Sync Service"},
        @{Name = "Set Network Private"; Command = "Set-NetConnectionProfile -NetworkCategory Private"; Description = "Set Network Category to Private"},
        @{Name = "Disable Terminal Service"; Command = "Stop-Service TermService -Force -ErrorAction SilentlyContinue; Set-Service TermService -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Terminal Service"},
        @{Name = "Disable Network Access Protection"; Command = "Stop-Service napagent -Force -ErrorAction SilentlyContinue; Set-Service napagent -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Network Access Protection"},
        @{Name = "Disable MSMQ Container"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-Container /NoRestart"; Description = "Disable MSMQ Container"},
        @{Name = "Disable MSMQ Triggers"; Command = "dism /online /Disable-Feature /FeatureName:Msmq-Triggers /NoRestart"; Description = "Disable MSMQ Triggers"},
        @{Name = "Disable MSMQ AD Integration"; Command = "dism /online /Disable-Feature /FeatureName:Msmq-ADIntegration /NoRestart"; Description = "Disable MSMQ AD Integration"},
        @{Name = "Disable IIS Web Server Role"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebServerRole /NoRestart"; Description = "Disable IIS Web Server Role"},
        @{Name = "Disable Show Info Tip"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'ShowInfoTip' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Show Info Tip"},
        @{Name = "Disable Ncd Auto Flow"; Command = "Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' -Name 'NcdAutoFlow' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Ncd Auto Flow"},
        @{Name = "Disable Media Playback"; Command = "dism /online /Disable-Feature /FeatureName:MediaPlayback /NoRestart"; Description = "Disable Media Playback"},
        @{Name = "Disable IIS Hostable Web Core"; Command = "dism /online /Disable-Feature /FeatureName:IIS-HostableWebCore /NoRestart"; Description = "Disable IIS Hostable Web Core"},
        @{Name = "Disable Direct Play"; Command = "dism /online /Disable-Feature /FeatureName:DirectPlay /NoRestart"; Description = "Disable Direct Play"},
        @{Name = "Disable Data Center Bridging"; Command = "dism /online /Disable-Feature /FeatureName:DataCenterBridging /NoRestart"; Description = "Disable Data Center Bridging"},
        @{Name = "Disable Netlogon"; Command = "Stop-Service Netlogon -Force -ErrorAction SilentlyContinue; Set-Service Netlogon -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Netlogon"},
        @{Name = "Disable Activities History"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\History' -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Activities History"},
        @{Name = "Disable Activities Roamed"; Command = "Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\RoamedHistory' -Name 'Enabled' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable Activities Roamed History"},
        @{Name = "Disable Hyper-V Tools All"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Tools-All /NoRestart"; Description = "Disable Hyper-V Tools All"},
        @{Name = "Disable Hyper-V Hypervisor"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart"; Description = "Disable Hyper-V Hypervisor"},
        @{Name = "Disable Hyper-V Services"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Services /NoRestart"; Description = "Disable Hyper-V Services"},
        @{Name = "Disable MSMQ Server"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-Server /NoRestart"; Description = "Disable MSMQ Server"},
        @{Name = "Disable IIS ASPNET"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ASPNET /NoRestart"; Description = "Disable IIS ASP.NET"},
        @{Name = "Disable IIS Common Http"; Command = "dism /online /Disable-Feature /FeatureName:IIS-CommonHttpFeatures /NoRestart"; Description = "Disable IIS Common HTTP Features"},
        @{Name = "Disable IIS Health Diagnostics"; Command = "dism /online /Disable-Feature /FeatureName:IIS-HealthAndDiagnostics /NoRestart"; Description = "Disable IIS Health and Diagnostics"},
        @{Name = "Disable IIS Management Console"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ManagementConsole /NoRestart"; Description = "Disable IIS Management Console"},
        @{Name = "Disable IIS Request Filtering"; Command = "dism /online /Disable-Feature /FeatureName:IIS-RequestFiltering /NoRestart"; Description = "Disable IIS Request Filtering"},
        @{Name = "Disable IIS Static Content"; Command = "dism /online /Disable-Feature /FeatureName:IIS-StaticContent /NoRestart"; Description = "Disable IIS Static Content"},
        @{Name = "Disable IIS Web Server"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebServer /NoRestart"; Description = "Disable IIS Web Server"},
        @{Name = "Disable WSL"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /NoRestart"; Description = "Disable Windows Subsystem for Linux"},
        @{Name = "Disable Containers"; Command = "dism /online /Disable-Feature /FeatureName:Containers /NoRestart"; Description = "Disable Containers"},
        @{Name = "Disable WCF Http Activation45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-Http-Activation45 /NoRestart"; Description = "Disable WCF HTTP Activation 4.5"},
        @{Name = "Disable WCF Msmq Activation45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-MSMQ-Activation45 /NoRestart"; Description = "Disable WCF MSMQ Activation 4.5"},
        @{Name = "Disable WCF Pipe Activation45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-Pipe-Activation45 /NoRestart"; Description = "Disable WCF Pipe Activation 4.5"},
        @{Name = "Disable WCF Tcp Activation45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-TCP-Activation45 /NoRestart"; Description = "Disable WCF TCP Activation 4.5"},
        @{Name = "Disable WCF Tcp PortSharing45"; Command = "dism /online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /NoRestart"; Description = "Disable WCF TCP Port Sharing 4.5"},
        @{Name = "Disable Windows Identity Foundation"; Command = "dism /online /Disable-Feature /FeatureName:Windows-Identity-Foundation /NoRestart"; Description = "Disable Windows Identity Foundation"},
        @{Name = "Disable Device Association Service"; Command = "Stop-Service DeviceAssociationService -Force -ErrorAction SilentlyContinue; Set-Service DeviceAssociationService -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Device Association Service"},
        @{Name = "Disable Optimal Transfer Client"; Command = "Stop-Service otc -Force -ErrorAction SilentlyContinue; Set-Service otc -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Optimal Transfer Client"},
        @{Name = "Disable DNS Enable Multicast"; Command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Force -ErrorAction SilentlyContinue"; Description = "Disable DNS Enable Multicast"},
        @{Name = "Disable Windows Error Reporting"; Command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Value 1 -Force -ErrorAction SilentlyContinue"; Description = "Disable Windows Error Reporting"},
        @{Name = "Cleanup Component Store"; Command = "dism /online /Cleanup-Image /StartComponentCleanup /NoRestart"; Description = "Cleanup Component Store"},
        @{Name = "Disable SmbDirect"; Command = "dism /online /Disable-Feature /FeatureName:SmbDirect /NoRestart"; Description = "Disable SMB Direct"},
        @{Name = "Disable IIS WebSockets"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebSockets /NoRestart"; Description = "Disable IIS WebSockets"},
        @{Name = "Disable IIS Windows Authentication"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WindowsAuthentication /NoRestart"; Description = "Disable IIS Windows Authentication"},
        @{Name = "Disable IIS Certificate Mapping"; Command = "dism /online /Disable-Feature /FeatureName:IIS-IISCertificateMappingAuthentication /NoRestart"; Description = "Disable IIS Certificate Mapping Authentication"},
        @{Name = "Disable IIS Digest Authentication"; Command = "dism /online /Disable-Feature /FeatureName:IIS-DigestAuthentication /NoRestart"; Description = "Disable IIS Digest Authentication"},
        @{Name = "Disable IIS Client Certificate"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ClientCertificateMappingAuthentication /NoRestart"; Description = "Disable IIS Client Certificate Mapping"},
        @{Name = "Disable IIS Basic Authentication"; Command = "dism /online /Disable-Feature /FeatureName:IIS-BasicAuthentication /NoRestart"; Description = "Disable IIS Basic Authentication"},
        @{Name = "Disable IIS URL Authorization"; Command = "dism /online /Disable-Feature /FeatureName:IIS-URLAuthorization /NoRestart"; Description = "Disable IIS URL Authorization"},
        @{Name = "Disable IIS Static Content"; Command = "dism /online /Disable-Feature /FeatureName:IIS-StaticContent /NoRestart"; Description = "Disable IIS Static Content"},
        @{Name = "Disable IIS Request Filtering"; Command = "dism /online /Disable-Feature /FeatureName:IIS-RequestFiltering /NoRestart"; Description = "Disable IIS Request Filtering"},
        @{Name = "Disable IIS Http Logging"; Command = "dism /online /Disable-Feature /FeatureName:IIS-HttpLogging /NoRestart"; Description = "Disable IIS HTTP Logging"},
        @{Name = "Disable IIS Http Errors"; Command = "dism /online /Disable-Feature /FeatureName:IIS-HttpErrors /NoRestart"; Description = "Disable IIS HTTP Errors"},
        @{Name = "Disable IIS Health Diagnostics"; Command = "dism /online /Disable-Feature /FeatureName:IIS-HealthAndDiagnostics /NoRestart"; Description = "Disable IIS Health and Diagnostics"},
        @{Name = "Disable IIS Common Http Features"; Command = "dism /online /Disable-Feature /FeatureName:IIS-CommonHttpFeatures /NoRestart"; Description = "Disable IIS Common HTTP Features"},
        @{Name = "Disable IIS Application Development"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ApplicationDevelopment /NoRestart"; Description = "Disable IIS Application Development"},
        @{Name = "Disable IIS Web Server"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebServer /NoRestart"; Description = "Disable IIS Web Server"},
        @{Name = "Disable TIFF IFilter"; Command = "dism /online /Disable-Feature /FeatureName:TIFFIFilter /NoRestart"; Description = "Disable TIFF IFilter"},
        @{Name = "Disable MSMQ Triggers"; Command = "dism /online /Disable-Feature /FeatureName:Msmq-Triggers /NoRestart"; Description = "Disable MSMQ Triggers"},
        @{Name = "Disable MSMQ AD Integration"; Command = "dism /online /Disable-Feature /FeatureName:Msmq-ADIntegration /NoRestart"; Description = "Disable MSMQ AD Integration"},
        @{Name = "Disable MSMQ Server"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-Server /NoRestart"; Description = "Disable MSMQ Server"},
        @{Name = "Disable Work Folders Client"; Command = "dism /online /Disable-Feature /FeatureName:WorkFolders-Client /NoRestart"; Description = "Disable Work Folders Client"},
        @{Name = "Disable Containers"; Command = "dism /online /Disable-Feature /FeatureName:Containers /NoRestart"; Description = "Disable Containers"},
        @{Name = "Disable Windows Media Player"; Command = "dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart"; Description = "Disable Windows Media Player"},
        @{Name = "Disable TIFF IFilter"; Command = "dism /online /Disable-Feature /FeatureName:TIFFIFilter /NoRestart"; Description = "Disable TIFF IFilter"},
        @{Name = "Disable MSRDC Infrastructure"; Command = "dism /Online /Disable-Feature /FeatureName:MSRDC-Infrastructure /NoRestart"; Description = "Disable MSRDC Infrastructure"},
        @{Name = "Disable Printing Foundation Features"; Command = "dism /Online /Disable-Feature /FeatureName:Printing-Foundation-Features /NoRestart"; Description = "Disable Printing Foundation Features"},
        @{Name = "Disable App Model Unlock"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock' /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 0 /f"; Description = "Disable App Model Unlock"},
        @{Name = "Disable Quality Windows Audio Video"; Command = "Stop-Service -Name 'QWAVE' -Force; Set-Service -Name 'QWAVE' -StartupType Disabled"; Description = "Disable Quality Windows Audio Video"},
        @{Name = "Disable Setting Sync Personalization"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization' /v 'Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Setting Sync Personalization"},
        @{Name = "Disable Setting Sync Theme"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Theme' /v 'Enabled' /t REG_DWORD /d 0 /f"; Description = "Disable Setting Sync Theme"},
        @{Name = "Disable Workplace Join"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WorkplaceJoin' /v 'EnableSharedExperiences' /t REG_DWORD /d 0 /f"; Description = "Disable Workplace Join"},
        @{Name = "Disable Cloud Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Clipboard' /v 'EnableCloudClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Cloud Clipboard"},
        @{Name = "Disable SmartScreen Policy"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen' /v 'EnableSmartScreen' /t REG_DWORD /d 0 /f"; Description = "Disable SmartScreen Policy"},
        @{Name = "Disable Sensor Service"; Command = "Stop-Service -Name 'SensrSvc' -Force; Set-Service -Name 'SensrSvc' -StartupType Disabled"; Description = "Disable Sensor Service"},
        @{Name = "Disable Network Connected Devices"; Command = "Stop-Service -Name 'NcdAutoSetup' -Force; Set-Service -Name 'NcdAutoSetup' -StartupType Disabled"; Description = "Disable Network Connected Devices Auto-Setup"},
        @{Name = "Disable NTFS Compression"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v 'NtfsDisableCompression' /t REG_DWORD /d 1 /f"; Description = "Disable NTFS Compression"},
        @{Name = "Disable Windows Connection Manager"; Command = "Stop-Service -Name 'Wcmsvc' -Force; Set-Service -Name 'Wcmsvc' -StartupType Disabled"; Description = "Disable Windows Connection Manager"},
        @{Name = "Disable Device Classes Allow"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{a72671a0-7170-11de-8422-001d92d4b9b0}\Device\0000000000000000\DeviceParameters' /v 'AllowDriverVerification' /t REG_DWORD /d 0 /f"; Description = "Disable Device Classes Allow Driver Verification"},
        @{Name = "Disable Startup Delay"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'StartupDelayInMSec' /t REG_DWORD /d 0 /f"; Description = "Disable Startup Delay"},
        @{Name = "Disable SSTP Service"; Command = "Stop-Service -Name 'SstpSvc' -Force; Set-Service -Name 'SstpSvc' -StartupType Disabled"; Description = "Disable SSTP Service"},
        @{Name = "Disable Performance Logs Alerts"; Command = "Stop-Service -Name 'pla' -Force; Set-Service -Name 'pla' -StartupType Disabled"; Description = "Disable Performance Logs & Alerts"},
        @{Name = "Disable Remote Desktop Configuration"; Command = "Stop-Service -Name 'SessionEnv' -Force; Set-Service -Name 'SessionEnv' -StartupType Disabled"; Description = "Disable Remote Desktop Configuration"},
        @{Name = "Disable Cloud Files Filter"; Command = "sc.exe config CldFlt start=disabled"; Description = "Disable Cloud Files Filter"},
        @{Name = "Disable BranchCache"; Command = "Stop-Service -Name 'PeerDistSvc' -Force; Set-Service -Name 'PeerDistSvc' -StartupType Disabled"; Description = "Disable BranchCache"},
        @{Name = "Disable Themes"; Command = "Stop-Service -Name 'Themes' -Force; Set-Service -Name 'Themes' -StartupType Disabled"; Description = "Disable Themes"},
        @{Name = "Disable Containers Disposable Client VM"; Command = "Disable-WindowsOptionalFeature -Online -FeatureName 'Containers-DisposableClientVM' -NoRestart"; Description = "Disable Containers Disposable Client VM"},
        @{Name = "Disable Data Sharing Service"; Command = "Stop-Service -Name 'DsSvc' -Force; Set-Service -Name 'DsSvc' -StartupType Disabled"; Description = "Disable Data Sharing Service"},
        @{Name = "Disable UE-V Agent Service"; Command = "Stop-Service -Name 'UevAgentService' -Force; Set-Service -Name 'UevAgentService' -StartupType Disabled"; Description = "Disable UE-V Agent Service"},
        @{Name = "Disable USB Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*UsbTm*'} | Disable-ScheduledTask"; Description = "Disable USB Tasks"},
        @{Name = "Disable WaaSMedic Tasks"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*WaaSMedic*'} | Disable-ScheduledTask"; Description = "Disable WaaSMedic Tasks"},
        @{Name = "Disable Compatibility Appraiser"; Command = "Get-ScheduledTask | Where-Object {`$_.TaskName -like '*CompatibilityAppraiser*'} | Disable-ScheduledTask"; Description = "Disable Compatibility Appraiser"},
        @{Name = "Disable Input Personalization"; Command = "reg add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t REG_DWORD /d 1 /f; reg add 'HKCU\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t REG_DWORD /d 1 /f"; Description = "Disable Input Personalization"},
        @{Name = "Disable Accepted Privacy Policy"; Command = "reg add 'HKCU\Software\Microsoft\InputPersonalization' /v 'AcceptedPrivacyPolicy' /t REG_DWORD /d 0 /f"; Description = "Disable Accepted Privacy Policy"},
        @{Name = "Disable Speech Recognition"; Command = "Stop-Service -Name 'SpeechRecognition' -ErrorAction SilentlyContinue; Set-Service -Name 'SpeechRecognition' -StartupType Disabled -ErrorAction SilentlyContinue"; Description = "Disable Speech Recognition"},
        @{Name = "Disable Windows Update AU"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoWindowsUpdate' /t REG_DWORD /d 1 /f"; Description = "Disable Windows Update Automatic Updates"},
        @{Name = "Disable Allow WUfB"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'AllowWUfB' /t REG_DWORD /d 0 /f"; Description = "Disable Allow Windows Update for Business"},
        @{Name = "Disable Update Compliance Diagnostics"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowUpdateComplianceDiagnostics' /t REG_DWORD /d 0 /f"; Description = "Disable Update Compliance Diagnostics"},
        @{Name = "Disable Device Search History"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'DeviceSearchHistoryEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Device Search History"},
        @{Name = "Disable Search Only Local"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current' /v 'SearchOnlyLocal' /t REG_DWORD /d 1 /f"; Description = "Disable Search Only Local"},
        @{Name = "Disable Device Search History"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'IsDeviceSearchHistoryEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Device Search History"},
        @{Name = "Disable Search Box App Recommendations"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'SearchboxAppRecommendationsEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Search Box App Recommendations"},
        @{Name = "Disable Show Search Highlights"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings' /v 'ShowSearchHighlights' /t REG_DWORD /d 0 /f"; Description = "Disable Show Search Highlights"},
        @{Name = "Disable Bing Search Enabled"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'BingSearchEnabled' /t REG_DWORD /d 0 /f"; Description = "Disable Bing Search Enabled"},
        @{Name = "Disable Windows Consumer Features"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d 1 /f"; Description = "Disable Windows Consumer Features"},
        @{Name = "Disable Advertising Info Policy"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v 'DisabledByGroupPolicy' /t REG_DWORD /d 1 /f"; Description = "Disable Advertising Info by Group Policy"},
        @{Name = "Disable Allow Cortana"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search' /v 'AllowCortana' /t REG_DWORD /d 0 /f"; Description = "Disable Allow Cortana"},
        @{Name = "Disable Dynamic Search Box"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Search' /v 'EnableDynamicSearchBoxWebContent' /t REG_DWORD /d 0 /f"; Description = "Disable Dynamic Search Box Web Content"},
        @{Name = "Disable Windows Error Reporting Policy"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' /v 'Disabled' /t REG_DWORD /d 1 /f"; Description = "Disable Windows Error Reporting by Policy"},
        @{Name = "Disable Windows Error Reporting"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting' /v 'Disabled' /t REG_DWORD /d 1 /f"; Description = "Disable Windows Error Reporting"},
        @{Name = "Disable PowerShell Telemetry"; Command = "[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'User')"; Description = "Disable PowerShell Telemetry"},
        @{Name = "Disable Disk Diagnostic Data Collector"; Command = "schtasks /Change /TN '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' /Disable"; Description = "Disable Disk Diagnostic Data Collector"},
        @{Name = "Disable App Readiness SqmTask"; Command = "schtasks /Change /TN '\Microsoft\Windows\AppReadiness\SqmTask' /Disable"; Description = "Disable App Readiness SqmTask"},
        @{Name = "Disable Appx Deployment Client"; Command = "schtasks /Change /TN '\Microsoft\Windows\AppxDeploymentClient\SvcTrigger' /Disable"; Description = "Disable Appx Deployment Client SvcTrigger"},
        @{Name = "Disable Feature Settings Override"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverride /t REG_DWORD /d 3 /f; reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f"; Description = "Disable Feature Settings Override"},
        @{Name = "Disable Wim Mount"; Command = "Stop-Service -Name 'WimMount' -Force; Set-Service -Name 'WimMount' -StartupType Disabled"; Description = "Disable Windows Image Mounting"},
        @{Name = "Disable SvcHost Split Threshold"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\SvcHost' /v SvcHostSplitThresholdInBytes /t REG_DWORD /d 1 /f"; Description = "Disable SvcHost Split Threshold"},
        @{Name = "Disable 8.3 Name Creation"; Command = "fsutil 8dot3name set 1"; Description = "Disable 8.3 Name Creation"},
        @{Name = "Disable Windows Time"; Command = "Stop-Service -Name 'W32Time' -Force; Set-Service -Name 'W32Time' -StartupType Disabled"; Description = "Disable Windows Time"},
        @{Name = "Disable System Event Notification"; Command = "Stop-Service -Name 'SENS' -Force; Set-Service -Name 'SENS' -StartupType Disabled"; Description = "Disable System Event Notification"},
        @{Name = "Set Win32 Priority Separation"; Command = "reg add 'HKCU\Control Panel\PriorityControl' /v Win32PrioritySeparation /t REG_DWORD /d 2 /f"; Description = "Set Win32 Priority Separation"},
        @{Name = "Disable Legacy Print Notify"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Printing' /v 'EnableLegacyPrtNotify' /t REG_DWORD /d 0 /f"; Description = "Disable Legacy Print Notify"},
        @{Name = "Disable WSL"; Command = "dism.exe /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux /NoRestart"; Description = "Disable Windows Subsystem for Linux"},
        @{Name = "Disable No Process Contents"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoProcessContents' /t REG_DWORD /d 1 /f"; Description = "Disable Process Contents"},
        @{Name = "Disable DotNet Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\.NETFramework' /v 'DotNetTelemetryOff' /t REG_DWORD /d 1 /f"; Description = "Disable .NET Framework Telemetry"},
        @{Name = "Disable Do Not Show Feedback"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'DoNotShowFeedbackNotifications' /t REG_DWORD /d 1 /f"; Description = "Disable Do Not Show Feedback Notifications"},
        @{Name = "Disable DNS Multicast"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' /v 'EnableMulticast' /t REG_DWORD /d 0 /f"; Description = "Disable DNS Multicast"},
        @{Name = "Disable Disable Domain Creds"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' /v 'DisableDomainCreds' /t REG_DWORD /d 1 /f"; Description = "Disable Domain Credentials"},
        @{Name = "Disable IKEEXT"; Command = "Stop-Service 'IKEEXT' -Force; Set-Service 'IKEEXT' -StartupType Disabled"; Description = "Disable IKE and AuthIP IPsec Keying Modules"},
        @{Name = "Disable WFDS Con Mgr Svc"; Command = "Stop-Service 'WFDSConMgrSvc' -Force; Set-Service 'WFDSConMgrSvc' -StartupType Disabled"; Description = "Disable Wi-Fi Direct Services Connection Manager"},
        @{Name = "Disable Allow Cross Device Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'AllowCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Allow Cross Device Clipboard"},
        @{Name = "Disable Disable Location"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' /v 'DisableLocation' /t REG_DWORD /d 1 /f"; Description = "Disable Location and Sensors"},
        @{Name = "Disable Listview Alpha Select"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewAlphaSelect' /t REG_DWORD /d 0 /f"; Description = "Disable Listview Alpha Select"},
        @{Name = "Disable Listview Shadow"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ListviewShadow' /t REG_DWORD /d 0 /f"; Description = "Disable Listview Shadow"},
        @{Name = "Enable Show Comp Color"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'ShowCompColor' /t REG_DWORD /d 1 /f"; Description = "Enable Show Compressed Color"},
        @{Name = "Disable Performance Diagnostics Events"; Command = "wevtutil sl Microsoft-Windows-Diagnostics-Performance/Operational /e:false"; Description = "Disable Performance Diagnostics Events"},
        @{Name = "Disable Start Track Progs"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_TrackProgs' /t REG_DWORD /d 0 /f"; Description = "Disable Start Track Programs"},
        @{Name = "Disable Enable Cross Device Clipboard"; Command = "reg add 'HKCU\Software\Microsoft\Input\Settings' /v 'EnableCrossDeviceClipboard' /t REG_DWORD /d 0 /f"; Description = "Disable Enable Cross Device Clipboard"},
        @{Name = "Disable Hyper-V Management Clients"; Command = "dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Management-Clients /NoRestart"; Description = "Disable Hyper-V Management Clients"},
        @{Name = "Disable Device Information Task"; Command = "schtasks /Change /TN '\Microsoft\Windows\Device Information\Device' /Disable"; Description = "Disable Device Information Task"},
        @{Name = "Disable IIS ASPNET45"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ASPNET45 /NoRestart"; Description = "Disable IIS ASP.NET 4.5"},
        @{Name = "Disable IIS Application Init"; Command = "dism /online /Disable-Feature /FeatureName:IIS-ApplicationInit /NoRestart"; Description = "Disable IIS Application Init"},
        @{Name = "Disable IIS Web Server Management Tools"; Command = "dism /online /Disable-Feature /FeatureName:IIS-WebServerManagementTools /NoRestart"; Description = "Disable IIS Web Server Management Tools"},
        @{Name = "Disable MSMQ DCOM Proxy"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-DCOMProxy /NoRestart"; Description = "Disable MSMQ DCOM Proxy"},
        @{Name = "Disable MSMQ HTTP"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-HTTP /NoRestart"; Description = "Disable MSMQ HTTP Support"},
        @{Name = "Disable MSMQ Multicast"; Command = "dism /online /Disable-Feature /FeatureName:MSMQ-Multicast /NoRestart"; Description = "Disable MSMQ Multicast Support"},
        @{Name = "Disable Let Apps Access Calendar"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessCalendar' /t REG_DWORD /d 2 /f"; Description = "Disable Let Apps Access Calendar"},
        @{Name = "Disable Limit Enhanced Diagnostic"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'LimitEnhancedDiagnosticDataWindowsAnalytics' /t REG_DWORD /d 0 /f"; Description = "Disable Limit Enhanced Diagnostic Data"},
        @{Name = "Disable Allow Device Name In Telemetry"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowDeviceNameInTelemetry' /t REG_DWORD /d 0 /f"; Description = "Disable Allow Device Name In Telemetry"},
        @{Name = "Disable Limit Enhanced Diagnostic Analytics"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f"; Description = "Disable Limit Enhanced Diagnostic Data Windows Analytics"},
        @{Name = "Disable Auto Share Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v AutoShareServer /t REG_DWORD /d 0 /f"; Description = "Disable Auto Share Server"},
        @{Name = "Disable Auto Share Wks"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' /v AutoShareWks /t REG_DWORD /d 0 /f"; Description = "Disable Auto Share Workstation"},
        @{Name = "Disable PCT 1.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable PCT 1.0 Server"},
        @{Name = "Disable SSL 2.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable SSL 2.0 Server"},
        @{Name = "Disable SSL 3.0 Server"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable SSL 3.0 Server"},
        @{Name = "Disable Disable Automatic Restart SignOn"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f"; Description = "Disable Automatic Restart Sign-On"},
        @{Name = "Disable Shutdown Reason On"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' /v ShutdownReasonOn /t REG_DWORD /d 0 /f"; Description = "Disable Shutdown Reason On"},
        @{Name = "Disable Shutdown Reason UI"; Command = "reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability' /v ShutdownReasonUI /t REG_DWORD /d 0 /f"; Description = "Disable Shutdown Reason UI"},
        @{Name = "Cleanup Image Start Component Cleanup"; Command = "dism /online /Cleanup-Image /StartComponentCleanup /ResetBase"; Description = "Cleanup Image Start Component Cleanup Reset Base"}
    )
    Browsers = @(
        @{Name = "Disable Edge Prelaunch"; Command = "reg add 'HKCU\Software\Microsoft\Edge\Main' /v AllowPrelaunch /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Edge\Main' /v AllowTabPreloading /t REG_DWORD /d 0 /f"; Description = "Disable Edge Prelaunch"},
        @{Name = "Disable Edge New Tab Content"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Edge' /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\Microsoft\Edge' /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f"; Description = "Disable Edge New Tab Content"},
        @{Name = "Disable Edge Hubs Sidebar"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Edge' /v HubsSidebarEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Edge Hubs Sidebar"},
        @{Name = "Disable Edge Update Tasks"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f"; Description = "Disable Edge Update Shortcuts"},
        @{Name = "Disable Chrome Metrics"; Command = "reg add 'HKCU\Software\Policies\Google\Chrome' /v MetricsReportingEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\Google\Chrome' /v CrashReportingEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Chrome Metrics"},
        @{Name = "Disable Brave Metrics"; Command = "reg add 'HKCU\Software\Policies\BraveSoftware\Brave' /v MetricsReportingEnabled /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Policies\BraveSoftware\Brave' /v CrashReportingEnabled /t REG_DWORD /d 0 /f"; Description = "Disable Brave Metrics"}
    )
    Security = @(
        @{Name = "Disable Windows Defender"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' /v DisableAntiSpyware /t REG_DWORD /d 1 /f"; Description = "Disable Windows Defender"},
        @{Name = "Disable SmartScreen"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v SmartScreenEnabled /t REG_SZ /d 'Off' /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v EnableSmartScreen /t REG_DWORD /d 0 /f"; Description = "Disable SmartScreen"},
        @{Name = "Disable Windows Copilot"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot' /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f"; Description = "Disable Windows Copilot"},
        @{Name = "Disable Hypervisor"; Command = "bcdedit /set hypervisorlaunchtype off"; Description = "Disable Hypervisor"},
        @{Name = "Disable Virtualization Security"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f"; Description = "Disable Virtualization-Based Security"}
    )
    Apps = @(
        @{Name = "Remove Windows Feedback"; Command = "Get-AppxPackage *windowsfeedback* | Remove-AppxPackage; Get-AppxPackage *DiagnosticsHub* | Remove-AppxPackage"; Description = "Remove Windows Feedback App"},
        @{Name = "Remove Quick Assist"; Command = "Get-AppxPackage *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*QuickAssist*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Quick Assist"},
        @{Name = "Remove Windows Backup"; Command = "Get-AppxPackage *WindowsBackup* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*WindowsBackup*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Windows Backup"},
        @{Name = "Remove Your Phone"; Command = "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*YourPhone*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Your Phone"},
        @{Name = "Remove Get Started"; Command = "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage; Get-AppxProvisionedPackage -Online | Where-Object {`$_.DisplayName -like '*Getstarted*'} | Remove-AppxProvisionedPackage -Online"; Description = "Remove Get Started"}
    )
    Performance = @(
        @{Name = "Disable Windows Spotlight"; Command = "reg add 'HKCU\Software\Policies\Microsoft\Windows\CloudContent' /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f"; Description = "Disable Windows Spotlight"},
        @{Name = "Disable Game Bar"; Command = "reg add 'HKCU\Software\Microsoft\GameBar' /v ShowStartupPanel /t REG_DWORD /d 0 /f; taskkill /f /im GameBarPresenceWriter.exe"; Description = "Disable Game Bar"},
        @{Name = "Fast App Closing"; Command = "reg add 'HKCU\Control Panel\Desktop' /v WaitToKillAppTimeout /t REG_SZ /d '1000' /f; reg add 'HKCU\Control Panel\Desktop' /v HungAppTimeout /t REG_SZ /d '1000' /f"; Description = "Speed up App Closing"},
        @{Name = "Disable USB Selective Suspend"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Services\USB\Parameters' /v DisableSelectiveSuspend /t REG_DWORD /d 1 /f"; Description = "Disable USB Selective Suspend"},
        @{Name = "Disable NTFS Compression"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisableCompression /t REG_DWORD /d 1 /f"; Description = "Disable NTFS Compression"},
        @{Name = "Disable Last Access Update"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f"; Description = "Disable Last Access Update"},
        @{Name = "Disable 8.3 Names"; Command = "reg add 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem' /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f"; Description = "Disable 8.3 Name Creation"}
    )
    Privacy = @(
        @{Name = "Disable Activity History"; Command = "reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v PublishUserActivities /t REG_DWORD /d 0 /f; reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v UploadUserActivities /t REG_DWORD /d 0 /f"; Description = "Disable Activity History"},
        @{Name = "Disable Clipboard Cloud"; Command = "reg add 'HKCU\Software\Microsoft\Clipboard' /v EnableClipboardHistory /t REG_DWORD /d 0 /f; reg add 'HKCU\Software\Microsoft\Clipboard' /v EnableCloudClipboard /t REG_DWORD /d 0 /f"; Description = "Disable Cloud Clipboard"},
        @{Name = "Disable Advertising ID"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v Enabled /t REG_DWORD /d 0 /f"; Description = "Disable Advertising ID"},
        @{Name = "Disable Input Personalization"; Command = "reg add 'HKCU\Software\Microsoft\InputPersonalization' /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f; reg add 'HKCU\Software\Microsoft\InputPersonalization' /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f"; Description = "Disable Input Personalization"},
        @{Name = "Disable Location"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' /v Value /t REG_SZ /d Deny /f"; Description = "Disable Location Services"},
        @{Name = "Disable Notifications"; Command = "reg add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f"; Description = "Disable Toast Notifications"}
    )
}

# Function to create checkboxes
function Create-Checkbox {
    param($text, $location, $category, $tweakData)

    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Text = $text
    $checkBox.Location = $location
    $checkBox.AutoSize = $true
    $checkBox.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
    $checkBox.Tag = @{Category = $category; Data = $tweakData}
    $checkBox.Checked = $false

    return $checkBox
}

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "ChoomCore GUI - Windows Optimization Tool (Complete Version)"
$form.Size = New-Object System.Drawing.Size(1000, 700)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
$form.ForeColor = [System.Drawing.Color]::FromArgb(241, 241, 241)
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)

# Create tab control
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(960, 580)
$tabControl.BackColor = [System.Drawing.Color]::FromArgb(63, 63, 70)
$tabControl.ForeColor = [System.Drawing.Color]::FromArgb(241, 241, 241)
$form.Controls.Add($tabControl)

# Create tabs
$tabs = @{}
$categories = @("Services", "ScheduledTasks", "Registry", "Browsers", "Security", "Apps", "Performance", "Privacy")
$tabNames = @("System Services", "Scheduled Tasks", "Registry", "Browsers", "Security", "Applications", "Performance", "Privacy")

for ($i = 0; $i -lt $categories.Count; $i++) {
    $tabPage = New-Object System.Windows.Forms.TabPage
    $tabPage.Text = $tabNames[$i]
    $tabPage.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $tabPage.ForeColor = [System.Drawing.Color]::FromArgb(241, 241, 241)

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = "Fill"
    $panel.AutoScroll = $true
    $tabPage.Controls.Add($panel)

    $tabs[$categories[$i]] = @{TabPage = $tabPage; Panel = $panel; CheckBoxes = @()}

    $tabControl.Controls.Add($tabPage)
}

# Add checkboxes to tabs
$yPos = 10
foreach ($category in $categories) {
    $yPos = 10
    foreach ($tweak in $tweaksData[$category]) {
        $checkBox = Create-Checkbox -text "$($tweak.Description)" -location (New-Object System.Drawing.Point(10, $yPos)) -category $category -tweakData $tweak
        $tabs[$category].Panel.Controls.Add($checkBox)
        $tabs[$category].CheckBoxes += $checkBox
        $yPos += 25
    }
}

# Create buttons panel
$buttonPanel = New-Object System.Windows.Forms.Panel
$buttonPanel.Location = New-Object System.Drawing.Point(10, 600)
$buttonPanel.Size = New-Object System.Drawing.Size(960, 50)
$buttonPanel.BackColor = [System.Drawing.Color]::FromArgb(63, 63, 70)
$form.Controls.Add($buttonPanel)

# Select All button
$selectAllBtn = New-Object System.Windows.Forms.Button
$selectAllBtn.Text = "Select All"
$selectAllBtn.Location = New-Object System.Drawing.Point(10, 10)
$selectAllBtn.Size = New-Object System.Drawing.Size(100, 30)
$selectAllBtn.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$selectAllBtn.ForeColor = [System.Drawing.Color]::White
$selectAllBtn.FlatStyle = "Flat"
$buttonPanel.Controls.Add($selectAllBtn)

# Deselect All button
$deselectAllBtn = New-Object System.Windows.Forms.Button
$deselectAllBtn.Text = "Deselect All"
$deselectAllBtn.Location = New-Object System.Drawing.Point(120, 10)
$deselectAllBtn.Size = New-Object System.Drawing.Size(110, 30)
$deselectAllBtn.BackColor = [System.Drawing.Color]::FromArgb(108, 117, 125)
$deselectAllBtn.ForeColor = [System.Drawing.Color]::White
$deselectAllBtn.FlatStyle = "Flat"
$buttonPanel.Controls.Add($deselectAllBtn)

# Apply button
$applyBtn = New-Object System.Windows.Forms.Button
$applyBtn.Text = "Apply Tweaks"
$applyBtn.Location = New-Object System.Drawing.Point(780, 10)
$applyBtn.Size = New-Object System.Drawing.Size(170, 30)
$applyBtn.BackColor = [System.Drawing.Color]::FromArgb(40, 167, 69)
$applyBtn.ForeColor = [System.Drawing.Color]::White
$applyBtn.FlatStyle = "Flat"
$buttonPanel.Controls.Add($applyBtn)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Ready"
$statusLabel.Location = New-Object System.Drawing.Point(250, 15)
$statusLabel.AutoSize = $true
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 193, 7)
$buttonPanel.Controls.Add($statusLabel)

# Event handlers
$selectAllBtn.Add_Click({
    foreach ($category in $categories) {
        foreach ($checkBox in $tabs[$category].CheckBoxes) {
            $checkBox.Checked = $true
        }
    }
    $statusLabel.Text = "All tweaks selected"
})

$deselectAllBtn.Add_Click({
    foreach ($category in $categories) {
        foreach ($checkBox in $tabs[$category].CheckBoxes) {
            $checkBox.Checked = $false
        }
    }
    $statusLabel.Text = "All tweaks deselected"
})

$applyBtn.Add_Click({
    $selectedTweaks = @()
    foreach ($category in $categories) {
        foreach ($checkBox in $tabs[$category].CheckBoxes) {
            if ($checkBox.Checked) {
                $selectedTweaks += $checkBox.Tag.Data
            }
        }
    }

    if ($selectedTweaks.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please select at least one tweak to apply.", "No tweaks selected", "OK", "Warning")
        return
    }

    $result = [System.Windows.Forms.MessageBox]::Show("Are you sure you want to apply $($selectedTweaks.Count) tweak(s)? This action may require a restart.", "Confirm Application", "YesNo", "Question")

    if ($result -eq "Yes") {
        $statusLabel.Text = "Applying tweaks..."
        $form.Refresh()

        $appliedCount = 0
        foreach ($tweak in $selectedTweaks) {
            try {
                Invoke-Expression $tweak.Command
                $appliedCount++
                $statusLabel.Text = "Applied: $($appliedCount)/$($selectedTweaks.Count)"
                $form.Refresh()
                Start-Sleep -Milliseconds 100
            } catch {
                Write-Host "Error applying tweak: $($tweak.Name)" -ForegroundColor Red
            }
        }

        $statusLabel.Text = "Completed! $appliedCount tweak(s) applied"
        [System.Windows.Forms.MessageBox]::Show("$appliedCount tweak(s) applied successfully!`n`nA restart may be required for some changes.", "Application Complete", "OK", "Information")
    }
})

# Form closing event
$form.Add_FormClosing({
    $result = [System.Windows.Forms.MessageBox]::Show("Do you really want to exit ChoomCore GUI?", "Confirm Exit", "YesNo", "Question")
    if ($result -eq "No") {
        $_.Cancel = $true
    }
})

# Initialize form
$form.ShowDialog() | Out-Null
