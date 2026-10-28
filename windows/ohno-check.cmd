@echo off
setlocal EnableExtensions
rem Read-only diagnostic: this script makes no policy or configuration changes.
echo ========================================
echo OHNO SYSTEM CHECK - READ ONLY
echo ========================================
echo Windows version:
ver
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v UBR 2>nul
echo.
echo Processor architecture: %PROCESSOR_ARCHITECTURE%
if defined PROCESSOR_ARCHITEW6432 echo Native architecture: %PROCESSOR_ARCHITEW6432%
echo.
echo Service status: BFE, Windows Firewall, DNS Client, Windows Installer
for %%S in (BFE MpsSvc Dnscache msiserver) do (
  echo --- %%S ---
  sc query %%S 2>&1
)
echo.
echo Available native commands:
for %%S in (sc.exe reg.exe netsh.exe schtasks.exe) do (
  where %%S 2>nul
  if errorlevel 1 echo %%S not found
)
echo.
echo Managed-browser executables found at standard install paths:
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" echo Edge x86 install: present
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" echo Edge x64 install: present
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" echo Chrome x86 install: present
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" echo Chrome x64 install: present
echo.
echo Finished. A stopped service is different from a missing service.
echo Send this output to the developer if needed. No settings were changed.
pause
