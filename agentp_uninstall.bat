@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: =========================
:: Portnox AgentP full cleanup (Windows)
:: Tested on Win10/11 64-bit. Run as Administrator.
:: =========================

:: --- Admin check ---
>nul 2>&1 net session || (
  echo [ERROR] Please run this script as Administrator.
  exit /b 1
)

echo === Portnox AgentP cleanup starting... ===

:: --- Try graceful stop, then remove service ---
echo [*] Stopping service PortnoxAgentP (ignore errors if not present)...
sc stop "PortnoxAgentP" >nul 2>&1
timeout /t 2 /nobreak >nul
echo [*] Deleting service (ignore errors if not present)...
sc delete "PortnoxAgentP" >nul 2>&1

:: --- Kill any leftover processes ---
echo [*] Killing AgentP processes (if any)...
taskkill /f /im AgentP.exe >nul 2>&1
taskkill /f /im PortnoxAgentP.exe >nul 2>&1

:: --- Try Registry-based uninstall first (preferred) ---
set "UninstallCmd="
for /f "delims=" %%K in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Portnox AgentP" ^| findstr /I /R "^HKEY_"') do (
  for /f "tokens=2,*" %%a in ('reg query "%%K" /v "DisplayName" ^| findstr /I "DisplayName"') do (
    echo %%b | findstr /I /C:"Portnox AgentP" >nul && (
      for /f "tokens=2,*" %%x in ('reg query "%%K" /v "UninstallString" ^| findstr /I "UninstallString"') do set "UninstallCmd=%%y"
    )
  )
)

if not defined UninstallCmd (
  for /f "delims=" %%K in ('reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Portnox AgentP" ^| findstr /I /R "^HKEY_"') do (
    for /f "tokens=2,*" %%a in ('reg query "%%K" /v "DisplayName" ^| findstr /I "DisplayName"') do (
      echo %%b | findstr /I /C:"Portnox AgentP" >nul && (
        for /f "tokens=2,*" %%x in ('reg query "%%K" /v "UninstallString" ^| findstr /I "UninstallString"') do set "UninstallCmd=%%y"
      )
    )
  )
)

if defined UninstallCmd (
  echo [*] Found uninstall command:
  echo     %UninstallCmd%
  echo [*] Triggering silent uninstall...
  :: If it's an MSI, add quiet flags; otherwise try common quiet switches.
  echo %UninstallCmd% | find /I "msiexec" >nul
  if %errorlevel%==0 (
    start /wait "" cmd /c "%UninstallCmd% /qn /norestart"
  ) else (
    start /wait "" cmd /c "%UninstallCmd% /S /quiet /norestart"
  )
  timeout /t 2 /nobreak >nul
) else (
  echo [!] No uninstall entry found in registry; proceeding with MSI ProductCode attempt...
)

:: --- Attempt MSI uninstall by ProductCode (best-effort) ---
set "AGENTP_PCODE={FDA66F08-864B-4B94-8B07-C257B69E9F57}"
echo [*] Attempting MSI uninstall: %AGENTP_PCODE%
msiexec /x %AGENTP_PCODE% /qn /norestart
timeout /t 2 /nobreak >nul

:: --- Remove Program Files / ProgramData remnants ---
echo [*] Removing files/directories...
if exist "C:\Program Files\Portnox AgentP" (
  takeown /f "C:\Program Files\Portnox AgentP" /r /d y >nul 2>&1
  icacls "C:\Program Files\Portnox AgentP" /grant *S-1-5-32-544:F /t >nul 2>&1
  rmdir /s /q "C:\Program Files\Portnox AgentP" 2>nul
)

rmdir /s /q "C:\ProgramData\AgentP\Logs" 2>nul
rmdir /s /q "C:\ProgramData\AgentP" 2>nul

del /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Portnox\Portnox AgentP.lnk" 2>nul
rmdir /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Portnox" 2>nul

:: --- Registry cleanup (machine hives) ---
echo [*] Cleaning registry keys...

:: Custom URL protocol class (if any)
reg delete "HKLM\SOFTWARE\Classes\agentp\shell\open\command" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\agentp\DefaultIcon" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Classes\agentp" /f >nul 2>&1

:: Service node (if still around)
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PortnoxAgentP" /f >nul 2>&1

:: App keys
reg delete "HKLM\SOFTWARE\Portnox AgentP" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Wow6432Node\Portnox AgentP" /f >nul 2>&1

:: Startup (Run)
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Portnox AgentP" /f >nul 2>&1

:: Remove Uninstall entry (if still present)
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{FDA66F08-864B-4B94-8B07-C257B69E9F57}" /f >nul 2>&1

:: Optional: Tracing keys
reg delete "HKLM\SOFTWARE\Microsoft\Tracing\AgentP_RASAPI32" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Tracing\AgentP_RASMANCS" /f >nul 2>&1

:: --- Per-user crumbs (for loaded profiles) ---
echo [*] Cleaning per-user crumbs...
for /f "tokens=2 delims=\" %%S in ('reg query "HKU" ^| findstr /R /C:"HKEY_USERS\\S-1-"') do (
  set "SID=%%S"
  if /I not "!SID!"=="S-1-5-18" (
    reg delete "HKU\!SID!\SOFTWARE\Portnox" /f >nul 2>&1
    reg delete "HKU\!SID!\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /v "C:\Program Files\Portnox AgentP\AgentP.exe" /f >nul 2>&1
  )
)

:: --- Refresh icon cache (best-effort) ---
echo [*] Flushing icon cache (optional)...
ie4uinit.exe -ClearIconCache >nul 2>&1

echo === Cleanup complete. A reboot is recommended. ===
exit /b 0
