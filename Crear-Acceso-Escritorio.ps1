# Crear acceso directo de CLONADISCOS en el escritorio
$WshShell = New-Object -ComObject WScript.Shell
$Desktop = [Environment]::GetFolderPath('Desktop')
$Shortcut = $WshShell.CreateShortcut("$Desktop\CLONADISCOS.lnk")
$Shortcut.TargetPath = 'powershell.exe'
$Shortcut.Arguments = '-ExecutionPolicy Bypass -File "E:\_MEMMEM\_APPS\CLONADISCOS\_DEV\CLONADISCOS.ps1"'
$Shortcut.WorkingDirectory = 'E:\_MEMMEM\_APPS\CLONADISCOS\_DEV'
$Shortcut.IconLocation = 'shell32.dll,8'
$Shortcut.Description = 'CLONADISCOS - Clonador de discos'
$Shortcut.Save()

Write-Host ""
Write-Host "  [OK] Acceso directo creado en: $Desktop\CLONADISCOS.lnk" -ForegroundColor Green
Write-Host ""
