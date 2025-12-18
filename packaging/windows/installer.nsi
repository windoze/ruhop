; Ruhop VPN NSIS Installer Script

!include "MUI2.nsh"
!include "FileFunc.nsh"

; General
Name "Ruhop VPN"
OutFile "ruhop-installer.exe"
InstallDir "$PROGRAMFILES64\Ruhop"
InstallDirRegKey HKLM "Software\Ruhop" "InstallDir"
RequestExecutionLevel admin

; Version info
!define VERSION "0.1.0"
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Ruhop VPN"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileDescription" "Ruhop VPN Installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2024"

; Interface Settings
!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; Installer Section
Section "Install"
    SetOutPath "$INSTDIR"

    ; Install main executable
    File "..\..\target\release\ruhop.exe"

    ; Install wintun.dll to System32 for service compatibility
    SetOutPath "$SYSDIR"
    File "wintun.dll"

    ; Create config directory
    CreateDirectory "$APPDATA\Ruhop"

    ; Install example config if no config exists
    SetOutPath "$APPDATA\Ruhop"
    IfFileExists "$APPDATA\Ruhop\ruhop.toml" +2 0
    File /oname=$APPDATA\Ruhop\ruhop.toml.example "ruhop.toml.example"

    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\Ruhop"
    CreateShortCut "$SMPROGRAMS\Ruhop\Ruhop VPN.lnk" "$INSTDIR\ruhop.exe"
    CreateShortCut "$SMPROGRAMS\Ruhop\Uninstall.lnk" "$INSTDIR\uninstall.exe"

    ; Write registry keys
    WriteRegStr HKLM "Software\Ruhop" "InstallDir" "$INSTDIR"
    WriteRegStr HKLM "Software\Ruhop" "Version" "${VERSION}"

    ; Write uninstaller registry keys
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "DisplayName" "Ruhop VPN"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "DisplayVersion" "${VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "Publisher" "Ruhop"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "NoRepair" 1

    ; Get installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop" \
        "EstimatedSize" "$0"

    ; Create uninstaller
    SetOutPath "$INSTDIR"
    WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Windows Service Section (optional)
Section "Install as Windows Service" SecService
    ; Install the service
    nsExec::ExecToLog '"$INSTDIR\ruhop.exe" service install'
SectionEnd

; Uninstaller Section
Section "Uninstall"
    ; Stop and remove service if installed
    nsExec::ExecToLog '"$INSTDIR\ruhop.exe" service stop'
    nsExec::ExecToLog '"$INSTDIR\ruhop.exe" service uninstall'

    ; Remove files
    Delete "$INSTDIR\ruhop.exe"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove wintun.dll from System32
    Delete "$SYSDIR\wintun.dll"

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\Ruhop\Ruhop VPN.lnk"
    Delete "$SMPROGRAMS\Ruhop\Uninstall.lnk"
    RMDir "$SMPROGRAMS\Ruhop"

    ; Remove registry keys
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Ruhop"
    DeleteRegKey HKLM "Software\Ruhop"

    ; Note: We don't remove $APPDATA\Ruhop to preserve user config
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install Ruhop as a Windows service that starts automatically."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
