$WshShell = New-Object -comObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$Shortcut = $WshShell.CreateShortcut("$desktop\CLONADISCOS.lnk")
$Shortcut.TargetPath = 'powershell.exe'
$Shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "E:\_MEMMEM\_APPS\CLONADISCOS\CLONADISCOS.ps1"'
$Shortcut.WorkingDirectory = 'E:\_MEMMEM\_APPS\CLONADISCOS'
$Shortcut.IconLocation = 'E:\_MEMMEM\_APPS\CLONADISCOS\clonadiscos.ico'
$Shortcut.Description = 'CLONADISCOS - Clonador de discos ultra rapido'
$Shortcut.Save()
Write-Host "[OK] Acceso directo creado: $desktop\CLONADISCOS.lnk" -ForegroundColor Green
