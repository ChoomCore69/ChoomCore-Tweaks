Stop-Service "Connected User Experiences and Telemetry" -Force
Set-Service "Connected User Experiences and Telemetry" -StartupType Disabled
Stop-Service MapsBroker -Force
Set-Service MapsBroker -StartupType Disabled
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Recommendations" /t REG_DWORD /d 0 /f
Get-ScheduledTask | Where-Object {$_.TaskName -like "*XblGameSave*"} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskName -like "*MicrosoftEdge*" -or $_.TaskName -like "*OfficeClickToRun*"} | Disable-ScheduledTask
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
Stop-Service DiagTrack -Force
Set-Service DiagTrack -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
Stop-Service WerSvc -Force
Set-Service WerSvc -StartupType Disabled
Stop-Service DusmSvc -Force
Set-Service DusmSvc -StartupType Disabled
Stop-Service SCardSvr -Force
Set-Service SCardSvr -StartupType Disabled
Stop-Service WbioSrvc -Force
Set-Service WbioSrvc -StartupType Disabled
Stop-Service bthserv -Force
Set-Service bthserv -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Network" /v NoFileSharing /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Feedback" /v DisableFeedbackNotifications /t REG_DWORD /d 1 /f
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Edge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Edge\Main" /v AllowTabPreloading /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v AllowTabPreloading /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v NewTabPageContentEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v NewTabPageHideDefaultTopSites /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f
schtasks /Change /TN "\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineCore" /Disable
schtasks /Change /TN "\Microsoft\EdgeUpdate\EdgeUpdateTaskMachineUA" /Disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v CreateDesktopShortcutDefault /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Google\Chrome" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Google\Chrome" /v CrashReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v PrerenderFromOmnibox /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v MetricsReportingEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\BraveSoftware\Brave" /v CrashReportingEnabled /t REG_DWORD /d 0 /f
schtasks /Change /TN "\BraveSoftware\BraveUpdateTaskMachineCore" /Disable
schtasks /Change /TN "\BraveSoftware\BraveUpdateTaskMachineUA" /Disable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.WindowsStore" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v ToastEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Edge /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenAndTouch" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoRecentDocsMenu" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysShowMenus" /t REG_DWORD /d 1 /f
Stop-Service dmwappushservice -Force
Set-Service dmwappushservice -StartupType Disabled
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_QWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Autochk\" | Disable-ScheduledTask
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowRecommendations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
Get-PnpDevice | Where-Object { $_.FriendlyName -like "*touch*" -and $_.Status -eq "OK" } | Disable-PnpDevice -Confirm:$false
reg add "HKCU\Control Panel\Desktop" /v LogPixels /t REG_DWORD /d 96 /f
reg add "HKCU\Control Panel\Desktop" /v Win8DpiScaling /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
lodctr /Q
lodctr /R
lodctr /D
Stop-Service -Name DiagSvc -Force
Set-Service -Name DiagSvc -StartupType Disabled
Stop-Service lfsvc -Force
Set-Service lfsvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f
bcdedit /set hypervisorlaunchtype off
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v FolderContentsInfoTip /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowInfoTip /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\GameBar" /v ShowStartupPanel /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v HungAppTimeout /t REG_SZ /d 1000 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ActionCenterEnabled /t REG_DWORD /d 0 /f
Stop-Service SensorService -Force
Set-Service SensorService -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v ChatEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v DiagTrack /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAi /t REG_DWORD /d 0 /f
reg add "HKCU\Console" /v ForceV2 /t REG_DWORD /d 0 /f
taskkill /f /im GameBarPresenceWriter.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
Stop-Service -Name WpnUserService -Force
Set-Service -Name WpnUserService -StartupType Disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v value /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowDeviceNameInTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v EnableInPlace /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v EdgeTargetMargin /t REG_DWORD /d 0 /f
taskkill /f /im TextInputHost.exe
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\USB\Parameters" /v DisableSelectiveSuspend /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v StartupDelayInMSec /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v NoRecentDocsMenu /t REG_DWORD /d 1 /f
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d 2 /f
Stop-Service "CDPUserSvc" -Force
Set-Service "CDPUserSvc" -StartupType Disabled
Stop-Service "PcaSvc" -Force
Set-Service "PcaSvc" -StartupType Disabled
Stop-Service "AppVClient" -Force
Set-Service "AppVClient" -StartupType Disabled
Get-ScheduledTask -TaskName "Consolidator" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "UsbCeip" | Disable-ScheduledTask
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f  
Stop-Service PhoneSvc -Force
Set-Service PhoneSvc -StartupType Disabled
Stop-Service MessagingService -Force
Set-Service MessagingService -StartupType Disabled
Stop-Service SharedAccess -Force
Set-Service SharedAccess -StartupType Disabled
Stop-Service RetailDemo -Force
Set-Service RetailDemo -StartupType Disabled
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "\Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /Disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
Stop-Service RemoteRegistry -Force
Set-Service RemoteRegistry -StartupType Disabled
Stop-Service SSDPSRV -Force
Set-Service SSDPSRV -StartupType Disabled
Stop-Service upnphost -Force
Set-Service upnphost -StartupType Disabled
Stop-Service iphlpsvc -Force
Set-Service iphlpsvc -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName Printing-PrintToPDFServices-Features -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName MediaPlayback -NoRestart
schtasks /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "\Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" /DisableStop-Service dmwappushservice -Force
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LsaCfgFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v Start /t REG_DWORD /d 4 /f
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Stop-Service -Name "EFS" -Force
Set-Service -Name "EFS" -StartupType Disabled
Stop-Service fdPHost -Force
Set-Service fdPHost -StartupType Disabled
Stop-Service FDResPub -Force
Set-Service FDResPub -StartupType Disabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EnableBDE /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EncryptionMethodWithXtsFdv /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v EncryptionMethodWithXtsOs /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v FDVEncryptionType /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v RDVDisableBDE /t REG_DWORD /d 1 /f
logman stop perfdiag -ets
Stop-Service -Name "DmEnrollmentSvc" -Force -ErrorAction SilentlyContinue
Set-Service -Name "DmEnrollmentSvc" -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
dism /Online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features /NoRestart
dism /Online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart
dism /Online /Disable-Feature /FeatureName:Internet-Explorer-Optional-amd64 /NoRestart
Get-AppxPackage *windowsfeedback* | Remove-AppxPackage
Get-AppxPackage *DiagnosticsHub* | Remove-AppxPackage
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Diagnosis-PLA/Operational" /v Enabled /t REG_DWORD /d 0 /f   
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational" /v Enabled /t REG_DWORD /d 0 /f
Get-AppxPackage *MicrosoftCorporationII.QuickAssist* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*QuickAssist*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *WindowsBackup* | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*WindowsBackup*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*YourPhone*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Getstarted*"} | Remove-AppxProvisionedPackage -Online
Get-AppxPackage *Microsoft.WindowsFamily* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*WindowsFamily*"} | Remove-AppxProvisionedPackage -Online 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
logman stop perfdiag -ets
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableCloudClipboard /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapAssist /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SnapFlyoutSuggest /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Recommendations /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f  
Stop-Service wisvc -Force  
Set-Service wisvc -StartupType Disabled  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f
Stop-Service FrameServer -Force  
Set-Service FrameServer -StartupType Disabled
Stop-Service SEMgrSvc -Force  
Set-Service SEMgrSvc -StartupType Disabled
Stop-Service PerceptionSimulation -Force  
Set-Service PerceptionSimulation -StartupType Disabled  
Stop-Service CaptureService -Force  
Set-Service CaptureService -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f    
reg add "HKCU\Software\Microsoft\Narrator" /v "UserPrefNarratorHotkey" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Narrator" /v "UserPrefStartNarratorOnStartup" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Narrator" /v "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v Configuration /t REG_SZ /d "" /f  
reg add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Accessibility" /v DebugOutput /t REG_DWORD /d 0 /f
Stop-Service BTAGService -Force
Set-Service BTAGService -StartupType Disabled
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility" /v SoundSentryFlags /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility" /v SoundSentryAnimation /t REG_DWORD /d 0 /f
Get-AppxPackage *Accessibility* | Remove-AppxPackage  
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Accessibility*"} | Remove-AppxProvisionedPackage -Online
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsEnabled" /t REG_DWORD /d 0 /f  
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsOnboardingComplete" /t REG_DWORD /d 1 /f  
reg add "HKCU\Software\Microsoft\Accessibility" /v "LiveCaptionsLanguage" /t REG_SZ /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v NOC_GLOBAL_SETTING_TOASTS_ENABLED /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v Enabled /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v Enabled /t REG_DWORD /d 0 /f
logman delete trace "Diagtrack-Listener"
bcdedit /set vsmlaunchtype Off  
Stop-Service RpcLocator -Force
Set-Service RpcLocator -StartupType Disabled
reg add "HKLM\SOFTWARE\Microsoft\Ole" /v EnableDCOM /t REG_SZ /d "N" /f
reg add "HKLM\SOFTWARE\Microsoft\Rpc" /v DCOMProtocol /t REG_MULTI_SZ /d "" /f
auditpol /set /category:* /success:disable /failure:disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsBackup" /v DisableBackup /t REG_DWORD /d 1 /f
Stop-Service BDESVC -Force
Set-Service BDESVC -StartupType Disabled
sc delete BDESVC
reg add "HKLM\SOFTWARE\Microsoft\COM3" /v DisableClassStore /t REG_DWORD /d 1 /f
sc.exe config KtmRm start= disabled
Stop-Service KtmRm -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableCompression /t REG_DWORD /d 1 /f
Stop-Service SensorDataService -Force
Set-Service SensorDataService -StartupType Disabled
Stop-Service SmsRouter -Force
Set-Service SmsRouter -StartupType Disabled
cmd /c "sc config CldFlt start=disabled"
sc.exe config storqosflt start=disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService" /v Start /t REG_DWORD /d 4 /f
& sc.exe config WiaRpc start= disabled
Stop-Service WiaRpc -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v SMBDeviceEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
Stop-Service DeviceAssociationBrokerSvc -Force
Set-Service DeviceAssociationBrokerSvc -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\TriggerInfo" /v Start /t REG_DWORD /d 4 /f
Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-PrintToPDFServices-Features" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart
Stop-Service -Name "cbdhsvc" -Force
Set-Service -Name "cbdhsvc" -StartupType Disabled
Stop-Service -Name "UdkUserSvc" -Force
Set-Service -Name "UdkUserSvc" -StartupType Disabled
Stop-Service -Name "WSAIFabricSvc" -Force
Set-Service -Name "WSAIFabricSvc" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell" /t REG_SZ /d "cmd.exe" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
Disable-WindowsOptionalFeature -Online -FeatureName "LegacyComponents" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "MSRDC-Infrastructure" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-Features" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -NoRestart
Stop-Service -Name "embeddedmode" -Force
Set-Service -Name "embeddedmode" -StartupType Disabled
Stop-Service -Name "icssvc" -Force
Set-Service -Name "icssvc" -StartupType Disabled
Stop-Service -Name "NaturalAuthentication" -Force
Set-Service -Name "NaturalAuthentication" -StartupType Disabled
Stop-Service -Name "HvHost" -Force
Set-Service -Name "HvHost" -StartupType Disabled
Stop-Service -Name "vmickvpexchange" -Force
Set-Service -Name "vmickvpexchange" -StartupType Disabled
Stop-Service -Name "vmicguestinterface" -Force
Set-Service -Name "vmicguestinterface" -StartupType Disabled
dism /online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2Root /NoRestart
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /NoRestart
dism /online /Disable-Feature /FeatureName:Printing-PrintToPDFServices-Features /NoRestart
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-All /NoRestart
dism /online /Disable-Feature /FeatureName:LegacyComponents /NoRestart
Stop-Service "WpcMonSvc" -Force ; Set-Service "WpcMonSvc" -StartupType Disabled
schtasks /Change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
Stop-Service -Name "AssignedAccessManagerSvc" -Force ; Set-Service -Name "AssignedAccessManagerSvc" -StartupType Disabled
Stop-Service -Name "BluetoothUserService" -Force ; Set-Service -Name "BluetoothUserService" -StartupType Disabled
Stop-Service -Name "CDPSvc" -Force ; Set-Service -Name "CDPSvc" -StartupType Disabled
Stop-Service -Name "CertPropSvc" -Force ; Set-Service -Name "CertPropSvc" -StartupType Disabled
Stop-Service -Name "SCPolicySvc" -Force ; Set-Service -Name "SCPolicySvc" -StartupType Disabled
Stop-Service -Name "TrkWks" -Force ; Set-Service -Name "TrkWks" -StartupType Disabled
Stop-Service -Name "Wecsvc" -Force ; Set-Service -Name "Wecsvc" -StartupType Disabled
Stop-Service -Name "WPDBusEnum" -Force ; Set-Service -Name "WPDBusEnum" -StartupType Disabled
Stop-Service -Name "WpnService" -Force ; Set-Service -Name "WpnService" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableAutoTray" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AllowGameBar" /t REG_DWORD /d 0 /f
Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage
Get-AppxPackage *Microsoft.VP9VideoExtensions* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Paint* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowRecommendations" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
dism /online /Disable-Feature /FeatureName:Printing-Foundation-InternetPrinting-Client /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-HTTP-Activation /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-NonHTTP-Activation /NoRestart
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v AutoSearch /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
Stop-Service RemoteAccess -Force
Set-Service RemoteAccess -StartupType Disabled
Stop-Service RasMan -Force
Set-Service RasMan -StartupType Disabled
reg add "HKCU\Software\Microsoft\GameBar" /v AllowGameBar /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices /t REG_DWORD /d 2 /f
Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage
Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -like "*Microsoft.ZuneVideo*"} | Remove-AppxProvisionedPackage -Online
Stop-Service lltdsvc -Force
Set-Service lltdsvc -StartupType Disabled
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
dism /Online /Disable-Feature /FeatureName:VirtualMachinePlatform /NoRestart
dism /Online /Disable-Feature /FeatureName:HypervisorPlatform /NoRestart
fsutil behavior set disablelastaccess 1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Accessibility\Configuration\VoiceAccess" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings\SearchHighlights" /v "IsOn" /t REG_DWORD /d 0 /f
Stop-Service vmms -Force -ErrorAction SilentlyContinue
Set-Service vmms -StartupType Disabled -ErrorAction SilentlyContinue
dism /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart
dism /online /Disable-Feature /FeatureName:TelnetClient /NoRestart
dism /online /Disable-Feature /FeatureName:SmbDirect /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-Services45 /NoRestart
"Microsoft.WidgetsPlatformRuntime","Microsoft.RawImageExtension","Microsoft.AVCEncoderVideoExtension","Microsoft.HEVCVideoExtension","Microsoft.MPEG2VideoExtension" | % {
    Get-AppxPackage -Name $_ -ErrorAction SilentlyContinue | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | ? { $_.PackageName -like "*$_*" } | Remove-AppxProvisionedPackage -Online
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesEnabled" -Value 0 -ForceSet-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Force
Set-Service -Name "DeviceSync" -StartupType Disabled -Status Stopped
Set-NetConnectionProfile -NetworkCategory Private
Stop-Service TermService -Force -ErrorAction SilentlyContinue
Set-Service TermService -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service napagent -Force -ErrorAction SilentlyContinue
Set-Service napagent -StartupType Disabled -ErrorAction SilentlyContinue
dism /online /Disable-Feature /FeatureName:MSMQ-Container /NoRestart
dism /online /Disable-Feature /FeatureName:Msmq-Triggers /NoRestart
dism /online /Disable-Feature /FeatureName:Msmq-ADIntegration /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WebServerRole /NoRestart
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NcdAutoFlow" -Value 0 -Force -ErrorAction SilentlyContinue
dism /online /Disable-Feature /FeatureName:MediaPlayback /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-HostableWebCore /NoRestart
dism /online /Disable-Feature /FeatureName:DirectPlay /NoRestart
dism /online /Disable-Feature /FeatureName:DataCenterBridging /NoRestart
Stop-Service Netlogon -Force -ErrorAction SilentlyContinue
Set-Service Netlogon -StartupType Disabled -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\History" -Name "Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Activities\RoamedHistory" -Name "Enabled" -Value 0 -Force -ErrorAction SilentlyContinue
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Tools-All /NoRestart
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Hypervisor /NoRestart
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Services /NoRestart
dism /online /Disable-Feature /FeatureName:MSMQ-Server /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-ASPNET /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-CommonHttpFeatures /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-HealthAndDiagnostics /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-ManagementConsole /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-RequestFiltering /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-StaticContent /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WebServer /NoRestart
dism /online /Disable-Feature /FeatureName:Microsoft-Windows-Subsystem-Linux /NoRestart
dism /online /Disable-Feature /FeatureName:Containers /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-Http-Activation45 /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-MSMQ-Activation45 /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-Pipe-Activation45 /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-TCP-Activation45 /NoRestart
dism /online /Disable-Feature /FeatureName:WCF-TCP-PortSharing45 /NoRestart
dism /online /Disable-Feature /FeatureName:Windows-Identity-Foundation /NoRestart
Stop-Service DeviceAssociationService -Force -ErrorAction SilentlyContinue
Set-Service DeviceAssociationService -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service otc -Force -ErrorAction SilentlyContinue
Set-Service otc -StartupType Disabled -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Force -ErrorAction SilentlyContinue
dism /online /Cleanup-Image /StartComponentCleanup /NoRestart
dism /online /Disable-Feature /FeatureName:SmbDirect /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WebSockets /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WindowsAuthentication /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-IISCertificateMappingAuthentication /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-DigestAuthentication /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-ClientCertificateMappingAuthentication /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-BasicAuthentication /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-URLAuthorization /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-StaticContent /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-RequestFiltering /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-HttpLogging /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-HttpErrors /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-HealthAndDiagnostics /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-CommonHttpFeatures /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-ApplicationDevelopment /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WebServer /NoRestart
dism /online /Disable-Feature /FeatureName:TIFFIFilter /NoRestart
dism /online /Disable-Feature /FeatureName:Msmq-Triggers /NoRestart
dism /online /Disable-Feature /FeatureName:Msmq-ADIntegration /NoRestart
dism /online /Disable-Feature /FeatureName:MSMQ-Server /NoRestart
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /NoRestart
dism /online /Disable-Feature /FeatureName:Containers /NoRestart
dism /online /Disable-Feature /FeatureName:WindowsMediaPlayer /NoRestart
dism /online /Disable-Feature /FeatureName:TIFFIFilter /NoRestart
dism /Online /Disable-Feature /FeatureName:MSRDC-Infrastructure /NoRestart
dism /Online /Disable-Feature /FeatureName:Printing-Foundation-Features /NoRestart
Stop-Service WCNCSVC -Force
Set-Service WCNCSVC -StartupType Disabled
Stop-Service WdiServiceHost -Force
Set-Service WdiServiceHost -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock" /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 0 /f
Stop-Service -Name "QWAVE" -Force
Set-Service -Name "QWAVE" -StartupType Disabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Theme" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WorkplaceJoin" /v "EnableSharedExperiences" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Clipboard" /v "EnableCloudClipboard" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
Stop-Service -Name "SensrSvc" -Force
Set-Service -Name "SensrSvc" -StartupType Disabled
Stop-Service -Name "NcdAutoSetup" -Force
Set-Service -Name "NcdAutoSetup" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d 1 /f
Stop-Service -Name "Wcmsvc" -Force
Set-Service -Name "Wcmsvc" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{a72671a0-7170-11de-8422-001d92d4b9b0}\Device\0000000000000000\DeviceParameters" /v "AllowDriverVerification" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
Stop-Service -Name "SstpSvc" -Force
Set-Service -Name "SstpSvc" -StartupType Disabled
Stop-Service -Name "pla" -Force
Set-Service -Name "pla" -StartupType Disabled
Stop-Service -Name "SessionEnv" -Force
Set-Service -Name "SessionEnv" -StartupType Disabled
sc.exe config CldFlt start=disabled
Stop-Service -Name "PeerDistSvc" -Force
Set-Service -Name "PeerDistSvc" -StartupType Disabled
Stop-Service -Name "Themes" -Force
Set-Service -Name "Themes" -StartupType Disabled
Disable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -NoRestart
Stop-Service -Name "DsSvc" -Force
Set-Service -Name "DsSvc" -StartupType Disabled
Stop-Service -Name "UevAgentService" -Force
Set-Service -Name "UevAgentService" -StartupType Disabled
Get-ScheduledTask | Where-Object {$_.TaskName -like "*UsbTm*"} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskName -like "*WaaSMedic*"} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskName -like "*CompatibilityAppraiser*"} | Disable-ScheduledTask
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
Stop-Service -Name "SpeechRecognition" -ErrorAction SilentlyContinue
Set-Service -Name "SpeechRecognition" -StartupType Disabled -ErrorAction SilentlyContinue
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoWindowsUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AllowWUfB" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowUpdateComplianceDiagnostics" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\DefaultAccount\Current" /v "SearchOnlyLocal" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SearchboxAppRecommendationsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "ShowSearchHighlights" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "EnableDynamicSearchBoxWebContent" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
[Environment]::SetEnvironmentVariable("POWERSHELL_TELEMETRY_OPTOUT", "1", "User")
schtasks /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "\Microsoft\Windows\AppReadiness\SqmTask" /Disable
schtasks /Change /TN "\Microsoft\Windows\AppxDeploymentClient\SvcTrigger" /Disable
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f
Stop-Service -Name "WimMount" -Force
Set-Service -Name "WimMount" -StartupType Disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SvcHost" /v SvcHostSplitThresholdInBytes /t REG_DWORD /d 1 /f
fsutil 8dot3name set 1
Stop-Service -Name "W32Time" -Force
Set-Service -Name "W32Time" -StartupType Disabled
Stop-Service -Name "SENS" -Force
Set-Service -Name "SENS" -StartupType Disabled
reg add "HKCU\Control Panel\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Printing" /v "EnableLegacyPrtNotify" /t REG_DWORD /d 0 /f
dism.exe /online /disable-feature /featurename:Microsoft-Windows-Subsystem-Linux /NoRestart
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoProcessContents" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework" /v "DotNetTelemetryOff" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f
Stop-Service "IKEEXT" -Force; Set-Service "IKEEXT" -StartupType Disabled
Stop-Service "WFDSConMgrSvc" -Force; Set-Service "WFDSConMgrSvc" -StartupType Disabled
reg add "HKCU\Software\Microsoft\Input\Settings" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d 1 /f
wevtutil sl Microsoft-Windows-Diagnostics-Performance/Operational /e:false
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Input\Settings" /v "EnableCrossDeviceClipboard" /t REG_DWORD /d 0 /f
dism /online /Disable-Feature /FeatureName:Microsoft-Hyper-V-Management-Clients /NoRestart
schtasks /Change /TN "\Microsoft\Windows\Device Information\Device" /Disable
dism /online /Disable-Feature /FeatureName:IIS-ASPNET45 /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-ApplicationInit /NoRestart
dism /online /Disable-Feature /FeatureName:IIS-WebServerManagementTools /NoRestart
dism /online /Disable-Feature /FeatureName:MSMQ-DCOMProxy /NoRestart
dism /online /Disable-Feature /FeatureName:MSMQ-HTTP /NoRestart
dism /online /Disable-Feature /FeatureName:MSMQ-Multicast /NoRestart
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v LimitEnhancedDiagnosticDataWindowsAnalytics /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableAutomaticRestartSignOn /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v ShutdownReasonOn /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v ShutdownReasonUI /t REG_DWORD /d 0 /f
dism /online /Cleanup-Image /StartComponentCleanup /ResetBase
