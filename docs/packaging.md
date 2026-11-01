# Packaging & Distribution Guide

## macOS Packaging

### 1. App Bundle Structure
When configured with CMake on macOS, the build generates a native `.app` bundle:
```
Xaynx Reverse Lab.app/
|-- Contents/
    |-- Info.plist
    |-- MacOS/
    |   `-- Xaynx Reverse Lab
    `-- Resources/
        `-- ghidra_scripts/
            `-- XrlExport.java
```

### 2. Standalone Deployment with `macdeployqt`
To bundle Qt frameworks and dylibs into the app bundle:
```bash
macdeployqt "build/src/ui/Xaynx Reverse Lab.app" -always-overwrite
```

### 3. DMG Creation
A release disk image can be assembled using `hdiutil`:
```bash
mkdir -p dist/dmg
cp -R "build/src/ui/Xaynx Reverse Lab.app" dist/dmg/
ln -s /Applications dist/dmg/Applications
hdiutil create -volname "Xaynx Reverse Lab" \
  -srcfolder dist/dmg -ov -format UDZO \
  "Xaynx-Reverse-Lab-macOS.dmg"
```

---

## Windows Packaging

### 1. Standalone Deployment with `windeployqt`
Using the MSVC 64-bit environment:
```powershell
cmake --build build --config Release
$ReleaseDir = "build\src\ui\Release"
windeployqt "$ReleaseDir\xaynx-reverse-lab.exe" --compiler-runtime --no-translations
```

### 2. Copy Assets
Ensure `ghidra_scripts` and Capstone runtime DLLs are placed alongside the executable:
```powershell
Copy-Item -Recurse -Force "ghidra_scripts" "$ReleaseDir\"
Copy-Item "$env:VCPKG_ROOT\installed\x64-windows\bin\capstone.dll" "$ReleaseDir\"
```

### 3. Installer (WiX / Inno Setup / NSIS)
Pack the `$ReleaseDir` directory using Inno Setup or NSIS to produce a single installer executable `XaynxReverseLab-Setup-x64.exe`.

