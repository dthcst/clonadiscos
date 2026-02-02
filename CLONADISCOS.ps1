# ===============================================================================
# CLONADISCOS v2.4.2 - CLONADOR DE DISCOS RAPIDO
# FIX: Start-Process -NoNewWindow -Wait (SIN redireccion) para mostrar progreso
# NEW: Monitor JSON, Update 250ms, ETA interpolado, timer colores
# Clona discos a velocidad maxima usando wimlib (GPL v3)
# Soporte completo para GPT/UEFI con particion EFI
# www.clonadiscos.com | www.discocloner.com
# ===============================================================================

# ===============================================================================
# AUTO-ELEVACION A ADMINISTRADOR
# ===============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    # Reiniciar con elevacion
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    try {
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
    } catch {
        Write-Host ""
        Write-Host "  [ERROR] Se requieren permisos de Administrador" -ForegroundColor Red
        Write-Host "  Click derecho -> Ejecutar como administrador" -ForegroundColor Yellow
        Write-Host ""
        Read-Host "  ENTER para salir"
    }
    exit
}

# Limpiar pantalla INMEDIATAMENTE para evitar flash de caracteres
Clear-Host

# ===============================================================================
# MUTEX - Evitar doble ejecucion (anti-listillos)
# ===============================================================================
$script:Mutex = New-Object System.Threading.Mutex($false, "Global\CLONADISCOS_SINGLE_INSTANCE")
if (-not $script:Mutex.WaitOne(0, $false)) {
    while ($true) {
        Write-Host ""
        Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  [!] CLONADISCOS YA ESTA EN EJECUCION                         ║" -ForegroundColor Red
        Write-Host "  ║  Solo puede haber una instancia a la vez.                     ║" -ForegroundColor Red
        Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Cierra la otra ventana de CLONADISCOS e intenta de nuevo." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [R] Reintentar    [X] Salir" -ForegroundColor Cyan
        Write-Host ""
        $resp = Read-Host "  Opcion"
        if ($resp -match "^[Rr]$") {
            # Reintentar mutex
            if ($script:Mutex.WaitOne(0, $false)) {
                break  # Mutex adquirido, continuar
            }
            Clear-Host
            continue
        }
        [Environment]::Exit(0)
    }
}

# Configurar encoding UTF-8 para la consola (silencioso)
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
    chcp 65001 2>&1 | Out-Null
} catch {}

# ===============================================================================
# HELPERS: CONSOLA SEGURA (funciona con entrada redirigida)
# ===============================================================================

function Test-ConsolaInteractiva {
    try {
        if ([Console]::IsInputRedirected) { return $false }
        $null = [Console]::KeyAvailable
        return $true
    } catch { return $false }
}

function Read-TeclaSafe {
    param([bool]$Intercept = $true)
    if (Test-ConsolaInteractiva) {
        try { return [Console]::ReadKey($Intercept) } catch {}
    }
    Write-Host ""
    Write-Host "    Tecla (ENTER=aceptar, X=salir): " -NoNewline -ForegroundColor Yellow
    $inp = Read-Host
    return [PSCustomObject]@{
        Key = if ([string]::IsNullOrEmpty($inp)) { "Enter" } elseif ($inp -match "^[0-9]$") { "D$inp" } else { $inp.ToUpper() }
        KeyChar = if ([string]::IsNullOrEmpty($inp)) { [char]13 } else { $inp[0] }
    }
}

function Get-CursorTopSafe {
    try {
        if (-not [Console]::IsOutputRedirected) { return [Console]::CursorTop }
    } catch {}
    return 0
}

function Test-KeyAvailableSafe {
    try {
        if (Test-ConsolaInteractiva) { return [Console]::KeyAvailable }
    } catch {}
    return $false
}

# Ocultar barras de progreso nativas de PowerShell (Format-Volume, etc.)
$ProgressPreference = 'SilentlyContinue'

# Cargar dependencias (silencioso si no existen - para modo standalone)
$depPath1 = "$PSScriptRoot\..\..\\_CORE\Funciones-Progreso.ps1"
$depPath2 = "$PSScriptRoot\..\..\\_CORE\Instalador-Apps.ps1"
if (Test-Path $depPath1) { . $depPath1 }
if (Test-Path $depPath2) { . $depPath2 }

# ===============================================================================
# CONFIGURACION
# ===============================================================================

$script:CONFIG = @{
    Version = "v2.4.0"
    BackupPath = "$env:USERPROFILE\Documents\ARCAMIA-MEMMEM\DiskImages"
    TempPath = "$env:TEMP\CLONADISCOS"
    LogPath = "$env:USERPROFILE\Documents\ARCAMIA-MEMMEM\Logs\CLONADISCOS"
    WimlibPath = "$PSScriptRoot\tools\wimlib-imagex.exe"
}

# ===============================================================================
# FUNCION: Descargar wimlib automaticamente
# ===============================================================================
function Install-Wimlib {
    $toolsPath = "$PSScriptRoot\tools"
    $wimlibExe = "$toolsPath\wimlib-imagex.exe"
    $wimlibUrl = "https://wimlib.net/downloads/wimlib-1.14.4-windows-x86_64-bin.zip"
    $zipPath = "$env:TEMP\wimlib.zip"

    if (Test-Path $wimlibExe) {
        return $true
    }

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  DESCARGANDO WIMLIB (primera ejecucion)                       ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  wimlib es la herramienta de clonado mas robusta para Windows." -ForegroundColor Gray
    Write-Host "  Licencia: GPL v3 (codigo abierto)" -ForegroundColor Gray
    Write-Host ""

    try {
        # Crear carpeta tools
        if (-not (Test-Path $toolsPath)) {
            New-Item -Path $toolsPath -ItemType Directory -Force | Out-Null
        }

        # Descargar
        Write-Host "  [1/3] Descargando desde wimlib.net..." -ForegroundColor Yellow
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $wimlibUrl -OutFile $zipPath -UseBasicParsing

        # Extraer
        Write-Host "  [2/3] Extrayendo..." -ForegroundColor Yellow
        $extractPath = "$env:TEMP\wimlib_extract"
        if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        # Copiar solo los archivos necesarios
        Write-Host "  [3/3] Instalando en tools/..." -ForegroundColor Yellow
        $binPath = Get-ChildItem -Path $extractPath -Recurse -Filter "wimlib-imagex.exe" | Select-Object -First 1
        if ($binPath) {
            $binDir = $binPath.DirectoryName
            Copy-Item "$binDir\*.exe" $toolsPath -Force
            Copy-Item "$binDir\*.dll" $toolsPath -Force -ErrorAction SilentlyContinue
        }

        # Limpiar
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue

        if (Test-Path $wimlibExe) {
            Write-Host ""
            Write-Host "  [OK] wimlib instalado correctamente" -ForegroundColor Green
            Write-Host ""
            return $true
        } else {
            throw "No se encontro wimlib-imagex.exe despues de extraer"
        }

    } catch {
        Write-Host ""
        Write-Host "  [ERROR] No se pudo descargar wimlib: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Descarga manual: https://wimlib.net/downloads/" -ForegroundColor Yellow
        Write-Host "  Extrae wimlib-imagex.exe en: $toolsPath" -ForegroundColor Yellow
        Write-Host ""
        return $false
    }
}

# Verificar/instalar wimlib
if (-not (Install-Wimlib)) {
    Read-Host "  ENTER para salir"
    exit
}

# Crear carpeta de logs si no existe
if (-not (Test-Path $script:CONFIG.LogPath)) {
    New-Item -Path $script:CONFIG.LogPath -ItemType Directory -Force | Out-Null
}

# Variable global para el log actual
$script:CurrentLogFile = $null

function Start-CloneLog {
    param([string]$Operation, [string]$Source, [string]$Destination)
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $script:CurrentLogFile = Join-Path $script:CONFIG.LogPath "CLONADISCOS_${timestamp}.log"
    
    # Header del log
    $header = @"
================================================================================
CLONADISCOS - LOG DE OPERACION
================================================================================
Fecha:       $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Operacion:   $Operation
Origen:      $Source
Destino:     $Destination
================================================================================

"@
    $header | Out-File -FilePath $script:CurrentLogFile -Encoding UTF8
    return $script:CurrentLogFile
}

function Write-CloneLog {
    param([string]$Message, [switch]$Error)
    if ($script:CurrentLogFile) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        $prefix = if ($Error) { "ERROR" } else { "INFO" }
        "[$timestamp] [$prefix] $Message" | Out-File -FilePath $script:CurrentLogFile -Append -Encoding UTF8
    }
}

function Stop-CloneLog {
    param([bool]$Success, [string]$Duration)
    if ($script:CurrentLogFile) {
        $footer = @"

================================================================================
FIN DE OPERACION
================================================================================
Estado:      $(if ($Success) { "COMPLETADO" } else { "CON ERRORES" })
Duracion:    $Duration
Log:         $script:CurrentLogFile
================================================================================
"@
        $footer | Out-File -FilePath $script:CurrentLogFile -Append -Encoding UTF8
    }
}

# ===============================================================================
# MONITOR JSON EXTERNO - Para GUI externa (estilo FREGONATOR)
# ===============================================================================
$script:MonitorFile = "$env:PUBLIC\clonadiscos_progress.json"
$script:MonitorData = @{
    Version = "2.4.0"
    Etapa = "Iniciando"
    Progreso = 0
    ProgresoGlobal = 0
    Velocidad = 0
    ETA = "--:--"
    TiempoTranscurrido = "00:00:00"
    ArchivoActual = ""
    ParticionActual = 0
    ParticionesTotal = 0
    BytesCopiadosGB = 0
    BytesTotalGB = 0
    Terminado = $false
    Error = $null
    UltimaActualizacion = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

function Update-Monitor {
    param(
        [string]$Etapa,
        [int]$Progreso,
        [int]$ProgresoGlobal,
        [double]$Velocidad,
        [string]$ETA,
        [string]$TiempoTranscurrido,
        [string]$ArchivoActual,
        [int]$ParticionActual,
        [int]$ParticionesTotal,
        [double]$BytesCopiadosGB,
        [double]$BytesTotalGB,
        [switch]$Terminado,
        [string]$Error,
        [string]$Log
    )

    # Actualizar solo los campos proporcionados
    if ($Etapa) { $script:MonitorData.Etapa = $Etapa }
    if ($PSBoundParameters.ContainsKey('Progreso')) { $script:MonitorData.Progreso = $Progreso }
    if ($PSBoundParameters.ContainsKey('ProgresoGlobal')) { $script:MonitorData.ProgresoGlobal = $ProgresoGlobal }
    if ($PSBoundParameters.ContainsKey('Velocidad')) { $script:MonitorData.Velocidad = [math]::Round($Velocidad, 1) }
    if ($ETA) { $script:MonitorData.ETA = $ETA }
    if ($TiempoTranscurrido) { $script:MonitorData.TiempoTranscurrido = $TiempoTranscurrido }
    if ($ArchivoActual) { $script:MonitorData.ArchivoActual = $ArchivoActual }
    if ($PSBoundParameters.ContainsKey('ParticionActual')) { $script:MonitorData.ParticionActual = $ParticionActual }
    if ($PSBoundParameters.ContainsKey('ParticionesTotal')) { $script:MonitorData.ParticionesTotal = $ParticionesTotal }
    if ($PSBoundParameters.ContainsKey('BytesCopiadosGB')) { $script:MonitorData.BytesCopiadosGB = [math]::Round($BytesCopiadosGB, 2) }
    if ($PSBoundParameters.ContainsKey('BytesTotalGB')) { $script:MonitorData.BytesTotalGB = [math]::Round($BytesTotalGB, 2) }
    if ($Terminado) { $script:MonitorData.Terminado = $true }
    if ($Error) { $script:MonitorData.Error = $Error }

    $script:MonitorData.UltimaActualizacion = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    # Escribir JSON (silencioso si falla)
    try {
        $script:MonitorData | ConvertTo-Json -Depth 3 | Out-File -FilePath $script:MonitorFile -Encoding UTF8 -Force
    } catch {}

    # Log opcional
    if ($Log) { Write-CloneLog $Log }
}

function Clear-Monitor {
    # Limpiar archivo de monitor al terminar
    try {
        if (Test-Path $script:MonitorFile) {
            Remove-Item $script:MonitorFile -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# ===============================================================================
# REPAIR-BOOTLOADER - Reparar arranque del disco clonado
# ===============================================================================

function Repair-BootLoader {
    param(
        [int]$DiskNumber
    )

    Write-Host ""
    Write-Host "  [REPARANDO BOOTLOADER]" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-CloneLog "Iniciando reparacion de bootloader para disco $DiskNumber"

    # Obtener info del disco
    $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
    if (-not $disk) {
        Write-Host "    [ERROR] No se puede acceder al disco $DiskNumber" -ForegroundColor Red
        Write-CloneLog "ERROR: No se puede acceder al disco $DiskNumber" -Error
        return $false
    }

    $partStyle = $disk.PartitionStyle  # GPT o MBR
    Write-Host "    Estilo de particion: $partStyle" -ForegroundColor Gray
    Write-CloneLog "Estilo de particion: $partStyle"

    # Obtener particiones del disco
    $partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue |
                  Where-Object { $_.DriveLetter } |
                  Sort-Object PartitionNumber

    if (-not $partitions -or $partitions.Count -eq 0) {
        Write-Host "    [ERROR] No se encontraron particiones con letra asignada" -ForegroundColor Red
        Write-CloneLog "ERROR: No hay particiones con letra asignada" -Error
        return $false
    }

    # Detectar particion de BOOT (pequena, <1GB, generalmente "System Reserved" o "EFI")
    $bootPartition = $partitions | Where-Object { $_.Size -lt 1GB } | Select-Object -First 1

    # Detectar particion de WINDOWS (tiene carpeta \Windows)
    $winPartition = $null
    foreach ($p in $partitions) {
        $winPath = "$($p.DriveLetter):\Windows"
        if (Test-Path $winPath) {
            $winPartition = $p
            break
        }
    }

    if (-not $winPartition) {
        Write-Host "    [ERROR] No se encontro particion de Windows" -ForegroundColor Red
        Write-CloneLog "ERROR: No se encontro particion con carpeta Windows" -Error
        return $false
    }

    $winLetter = $winPartition.DriveLetter
    Write-Host "    Particion Windows: $winLetter`:\" -ForegroundColor Gray
    Write-CloneLog "Particion Windows detectada: $winLetter`:\"

    # Para MBR: marcar particion de boot como ACTIVA
    if ($partStyle -eq "MBR" -and $bootPartition) {
        $bootLetter = $bootPartition.DriveLetter
        $bootPartNum = $bootPartition.PartitionNumber

        Write-Host "    Particion Boot: $bootLetter`:\ (Particion $bootPartNum)" -ForegroundColor Gray
        Write-Host "    Marcando particion $bootPartNum como ACTIVA..." -ForegroundColor Yellow
        Write-CloneLog "Marcando particion $bootPartNum como activa (MBR)"

        try {
            # Usar diskpart para marcar como activa
            $dpScript = @"
select disk $DiskNumber
select partition $bootPartNum
active
exit
"@
            $dpFile = "$env:TEMP\dp_active.txt"
            $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
            $result = & diskpart /s $dpFile 2>&1
            Remove-Item $dpFile -Force -ErrorAction SilentlyContinue

            # Verificar
            $checkPart = Get-Partition -DiskNumber $DiskNumber -PartitionNumber $bootPartNum
            if ($checkPart.IsActive) {
                Write-Host "    [OK] Particion marcada como ACTIVA" -ForegroundColor Green
                Write-CloneLog "Particion $bootPartNum marcada como activa correctamente"
            } else {
                Write-Host "    [!] No se pudo verificar estado activo" -ForegroundColor Yellow
                Write-CloneLog "WARN: No se pudo verificar estado activo"
            }
        } catch {
            Write-Host "    [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            Write-CloneLog "ERROR marcando activa: $($_.Exception.Message)" -Error
        }
    }

    # Ejecutar BCDBOOT
    Write-Host "    Ejecutando bcdboot..." -ForegroundColor Yellow

    # Determinar letra de destino del boot
    $bootDestLetter = if ($bootPartition) { $bootPartition.DriveLetter } else { $winLetter }

    # /f ALL = crear para BIOS y UEFI
    # /s X: = destino donde poner los archivos de boot
    # /l es-ES = idioma espanol
    $bcdbootCmd = "bcdboot $winLetter`:\Windows /s $bootDestLetter`: /f ALL /l es-ES"
    Write-Host "    Comando: $bcdbootCmd" -ForegroundColor DarkGray
    Write-CloneLog "Ejecutando: $bcdbootCmd"

    try {
        $bcdResult = & cmd /c $bcdbootCmd 2>&1
        $bcdOutput = $bcdResult -join "`n"

        if ($bcdOutput -match "correctamente|successfully|created") {
            Write-Host "    [OK] Archivos de arranque creados correctamente" -ForegroundColor Green
            Write-CloneLog "bcdboot completado: $bcdOutput"
        } else {
            Write-Host "    [!] bcdboot ejecutado: $bcdOutput" -ForegroundColor Yellow
            Write-CloneLog "bcdboot resultado: $bcdOutput"
        }
    } catch {
        Write-Host "    [ERROR] bcdboot fallo: $($_.Exception.Message)" -ForegroundColor Red
        Write-CloneLog "ERROR bcdboot: $($_.Exception.Message)" -Error
        return $false
    }

    Write-Host ""
    Write-Host "  [OK] BOOTLOADER REPARADO" -ForegroundColor Green
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-CloneLog "Reparacion de bootloader completada"
    Write-Host ""

    return $true
}

# ===============================================================================
# REFRESH EXPLORER - Forzar que Windows detecte cambios en discos
# ===============================================================================

function Refresh-Explorer {
    param([switch]$Silent)

    if (-not $Silent) {
        Write-Host ""
        Write-Host "    Refrescando Explorer..." -ForegroundColor Gray
    }

    # 1. Eliminar politica NoDrives si existe (oculta discos)
    $policyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    if (Test-Path $policyPath) {
        $nodrives = Get-ItemProperty $policyPath -Name NoDrives -ErrorAction SilentlyContinue
        if ($nodrives.NoDrives) {
            Remove-ItemProperty $policyPath -Name NoDrives -ErrorAction SilentlyContinue
        }
    }

    # 2. Notificar al shell que hubo cambios en unidades
    try {
        $shellNotify = @'
using System;
using System.Runtime.InteropServices;
public class ShellNotify {
    [DllImport("shell32.dll")]
    public static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);

    public static void NotifyDriveChange() {
        // SHCNE_DRIVEADD | SHCNE_DRIVEREMOVED | SHCNE_MEDIAINSERTED | SHCNE_UPDATEDIR
        SHChangeNotify(0x00000100, 0x0000, IntPtr.Zero, IntPtr.Zero);  // DRIVEADD
        SHChangeNotify(0x00008000, 0x0000, IntPtr.Zero, IntPtr.Zero);  // UPDATEDIR
        SHChangeNotify(0x8000000, 0x0000, IntPtr.Zero, IntPtr.Zero);   // ASSOCCHANGED
    }
}
'@
        Add-Type -TypeDefinition $shellNotify -ErrorAction SilentlyContinue
        [ShellNotify]::NotifyDriveChange()
    } catch {}

    # 3. Actualizar discos en Windows
    Get-Disk | ForEach-Object { Update-Disk -Number $_.Number -ErrorAction SilentlyContinue }

    # 4. Refrescar iconos del Explorer (sin reiniciarlo)
    try {
        $explorerWindows = (New-Object -ComObject Shell.Application).Windows()
        $explorerWindows | ForEach-Object { $_.Refresh() }
    } catch {}

    if (-not $Silent) {
        Write-Host "    [OK] Explorer refrescado" -ForegroundColor Green
    }
}

# ===============================================================================
# RESET EXPLORER - Reiniciar completamente el Explorador de Windows
# ===============================================================================

function Reset-WindowsExplorer {
    <#
    .SYNOPSIS
        Reinicia el Explorador de Windows y limpia cache de iconos/thumbnails
    .DESCRIPTION
        Util cuando hay problemas con discos que no aparecen, iconos corruptos,
        o el explorador se comporta de forma extraña.
    #>

    Clear-Host
    Show-Logo -Subtitulo "REFRESCAR EXPLORADOR DE WINDOWS"

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  OPCIONES DE REFRESCO                                         ║" -ForegroundColor Cyan
    Write-Host "  ╟───────────────────────────────────────────────────────────────╢" -ForegroundColor Cyan
    Write-Host "  ║  [1] Refresco SUAVE - Notificar cambios (rapido)              ║" -ForegroundColor White
    Write-Host "  ║  [2] Refresco MEDIO - Actualizar discos + iconos              ║" -ForegroundColor White
    Write-Host "  ║  [3] Refresco FUERTE - Reiniciar explorer.exe                 ║" -ForegroundColor Yellow
    Write-Host "  ║  [4] Refresco TOTAL - Limpiar cache + reiniciar explorer      ║" -ForegroundColor Red
    Write-Host "  ║  ─────────────────────────────────────────────────────────────║" -ForegroundColor DarkGray
    Write-Host "  ║  [X] Cancelar                                                 ║" -ForegroundColor Gray
    Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Selecciona opcion: " -NoNewline -ForegroundColor Yellow

    $key = (Read-TeclaSafe).KeyChar.ToString().ToUpper()
    Write-Host $key
    Write-Host ""

    switch ($key) {
        "1" {
            # Refresco suave
            Write-Host "    [*] Aplicando refresco suave..." -ForegroundColor Cyan
            Refresh-Explorer
            Write-Host ""
            Write-Host "    [OK] Refresco suave completado" -ForegroundColor Green
        }
        "2" {
            # Refresco medio
            Write-Host "    [*] Aplicando refresco medio..." -ForegroundColor Cyan
            Write-Host ""

            # 1. Actualizar todos los discos
            Write-Host "    [1/4] Actualizando discos..." -ForegroundColor Gray
            Get-Disk | ForEach-Object {
                Update-Disk -Number $_.Number -ErrorAction SilentlyContinue
            }

            # 2. Rescanear discos
            Write-Host "    [2/4] Rescaneando discos..." -ForegroundColor Gray
            "rescan" | diskpart | Out-Null

            # 3. Notificar cambios al shell
            Write-Host "    [3/4] Notificando al shell..." -ForegroundColor Gray
            Refresh-Explorer -Silent

            # 4. Refrescar iconos
            Write-Host "    [4/4] Refrescando iconos..." -ForegroundColor Gray
            try {
                $code = @'
using System;
using System.Runtime.InteropServices;
public class IconRefresh {
    [DllImport("shell32.dll")]
    public static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
                Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
                [IconRefresh]::Refresh()
            } catch {}

            Write-Host ""
            Write-Host "    [OK] Refresco medio completado" -ForegroundColor Green
        }
        "3" {
            # Reiniciar explorer.exe
            Write-Host "    [!] Reiniciando Explorer..." -ForegroundColor Yellow
            Write-Host "    (Las ventanas del explorador se cerraran)" -ForegroundColor DarkGray
            Write-Host ""

            # Matar y reiniciar explorer
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Process explorer.exe
            Start-Sleep -Seconds 2

            Write-Host "    [OK] Explorer reiniciado" -ForegroundColor Green
        }
        "4" {
            # Refresco total con limpieza de cache
            Write-Host "    [!] Aplicando refresco TOTAL..." -ForegroundColor Red
            Write-Host "    (Esto puede tardar unos segundos)" -ForegroundColor DarkGray
            Write-Host ""

            # 1. Limpiar cache de iconos
            Write-Host "    [1/5] Limpiando cache de iconos..." -ForegroundColor Gray
            $iconCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
            if (Test-Path $iconCache) {
                Get-ChildItem "$iconCache\iconcache*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
                Get-ChildItem "$iconCache\thumbcache*" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
            }

            # 2. Limpiar cache de thumbnails
            Write-Host "    [2/5] Limpiando cache de miniaturas..." -ForegroundColor Gray
            $thumbCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
            Get-ChildItem "$thumbCache\thumbcache_*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

            # 3. Eliminar politicas de ocultar discos (por si quedaron)
            Write-Host "    [3/5] Eliminando politicas de ocultacion..." -ForegroundColor Gray
            $policyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            if (Test-Path $policyPath) {
                Remove-ItemProperty $policyPath -Name NoDrives -ErrorAction SilentlyContinue
                Remove-ItemProperty $policyPath -Name NoViewOnDrive -ErrorAction SilentlyContinue
            }

            # 4. Matar explorer
            Write-Host "    [4/5] Reiniciando Explorer..." -ForegroundColor Gray
            Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3

            # 5. Reiniciar explorer
            Write-Host "    [5/5] Iniciando Explorer..." -ForegroundColor Gray
            Start-Process explorer.exe
            Start-Sleep -Seconds 2

            # Notificar cambios
            Refresh-Explorer -Silent

            Write-Host ""
            Write-Host "    [OK] Refresco TOTAL completado" -ForegroundColor Green
            Write-Host "    Los iconos pueden tardar unos segundos en regenerarse" -ForegroundColor DarkGray
        }
        default {
            Write-Host "    Operacion cancelada" -ForegroundColor Gray
            return
        }
    }

    Write-Host ""
    Write-Host "    Pulsa cualquier tecla para volver..." -ForegroundColor DarkGray
    Read-TeclaSafe | Out-Null
}

# ===============================================================================
# SISTEMA DE ESTADO Y RECUPERACION
# ===============================================================================

# Estado global de operacion
$script:OperationState = @{
    IsRunning       = $false
    IsCancelled     = $false
    CanResume       = $false
    Operation       = $null          # "RAW_CLONE", "FILE_CLONE", "CREATE_IMAGE", "RESTORE_IMAGE", "FORMAT", "WIPE"
    SourceDisk      = $null
    DestDisk        = $null
    ImagePath       = $null
    StartTime       = $null
    BytesCopied     = 0
    TotalBytes      = 0
    LastCheckpoint  = 0              # Para posible reanudacion
    TempFiles       = @()            # Archivos temporales a limpiar
    TempLetters     = @()            # Letras de unidad temporales asignadas
    StateFile       = $null          # Archivo de estado para recuperacion
}

# Archivo de estado para recuperacion entre sesiones
$script:StateFilePath = Join-Path $script:CONFIG.LogPath "CLONADISCOS_STATE.json"

function Initialize-OperationState {
    param(
        [string]$Operation,
        [int]$SourceDisk = -1,
        [int]$DestDisk = -1,
        [string]$ImagePath = "",
        [long]$TotalBytes = 0
    )

    $script:OperationState = @{
        IsRunning       = $true
        IsCancelled     = $false
        CanResume       = $false
        Operation       = $Operation
        SourceDisk      = $SourceDisk
        DestDisk        = $DestDisk
        ImagePath       = $ImagePath
        StartTime       = Get-Date
        BytesCopied     = 0
        TotalBytes      = $TotalBytes
        LastCheckpoint  = 0
        TempFiles       = @()
        TempLetters     = @()
        StateFile       = $script:StateFilePath
    }

    # Guardar estado a disco
    Save-OperationState

    return $script:OperationState
}

function Save-OperationState {
    try {
        $stateToSave = $script:OperationState.Clone()
        $stateToSave.StartTime = $stateToSave.StartTime.ToString("o")  # ISO 8601
        $stateToSave | ConvertTo-Json -Depth 3 | Out-File -FilePath $script:StateFilePath -Encoding UTF8 -Force
    } catch {}
}

function Load-OperationState {
    if (Test-Path $script:StateFilePath) {
        try {
            $loaded = Get-Content $script:StateFilePath -Raw | ConvertFrom-Json
            return $loaded
        } catch {
            return $null
        }
    }
    return $null
}

function Clear-OperationState {
    $script:OperationState.IsRunning = $false
    $script:OperationState.IsCancelled = $false

    # Eliminar archivo de estado
    if (Test-Path $script:StateFilePath) {
        Remove-Item $script:StateFilePath -Force -ErrorAction SilentlyContinue
    }
}

function Test-CancelRequested {
    # Detectar ESC, Q o Ctrl+C
    if (Test-KeyAvailableSafe) {
        $key = Read-TeclaSafe
        if ($key.Key -eq [ConsoleKey]::Escape -or
            $key.Key -eq [ConsoleKey]::Q -or
            ($key.Modifiers -eq [ConsoleModifiers]::Control -and $key.Key -eq [ConsoleKey]::C)) {
            $script:OperationState.IsCancelled = $true
            return $true
        }
    }
    return $false
}

function Invoke-SafeCleanup {
    <#
    .SYNOPSIS
        Limpieza segura de recursos tras cancelacion o error
    #>
    param([switch]$ShowProgress)

    if ($ShowProgress) {
        Write-Host ""
        Write-Host "    Realizando limpieza segura..." -ForegroundColor Gray
    }

    # 1. Cerrar streams abiertos
    if ($script:SrcStream) {
        try { $script:SrcStream.Close() } catch {}
        $script:SrcStream = $null
    }
    if ($script:DstStream) {
        try { $script:DstStream.Close() } catch {}
        $script:DstStream = $null
    }

    # 2. Quitar letras temporales asignadas
    foreach ($temp in $script:OperationState.TempLetters) {
        try {
            Remove-PartitionAccessPath -DiskNumber $temp.DiskNumber -PartitionNumber $temp.PartitionNumber -AccessPath "$($temp.Letter):\" -ErrorAction SilentlyContinue
            if ($ShowProgress) { Write-Host "      [OK] Quitada letra temporal $($temp.Letter):" -ForegroundColor Green }
        } catch {}
    }
    $script:OperationState.TempLetters = @()

    # 3. Poner discos offline de vuelta online
    if ($script:OperationState.DestDisk -ge 0) {
        try {
            Set-Disk -Number $script:OperationState.DestDisk -IsOffline $false -ErrorAction SilentlyContinue
            if ($ShowProgress) { Write-Host "      [OK] Disco destino puesto online" -ForegroundColor Green }
        } catch {}
    }

    # 4. Eliminar archivos temporales
    foreach ($tempFile in $script:OperationState.TempFiles) {
        if (Test-Path $tempFile) {
            try {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                if ($ShowProgress) { Write-Host "      [OK] Eliminado temporal: $tempFile" -ForegroundColor Green }
            } catch {}
        }
    }
    $script:OperationState.TempFiles = @()

    # 5. Actualizar estado
    $script:OperationState.IsRunning = $false
    Save-OperationState

    if ($ShowProgress) {
        Write-Host "    Limpieza completada." -ForegroundColor Green
    }
}

function Show-CancellationMessage {
    param(
        [string]$Operation,
        [long]$BytesCopied,
        [datetime]$StartTime,
        [switch]$CanResume
    )

    $elapsed = (Get-Date) - $StartTime
    $copiedGB = [math]::Round($BytesCopied / 1GB, 2)
    $elapsedStr = "$([math]::Floor($elapsed.TotalMinutes))m $([math]::Round($elapsed.Seconds))s"

    Write-Host ""
    Write-Host ""
    Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "    ║                   OPERACION CANCELADA                           ║" -ForegroundColor Yellow
    Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
    Write-Host "    ║  Operacion:       $("{0,-45}" -f $Operation)║" -ForegroundColor White
    Write-Host "    ║  Progreso:        $("{0,-45}" -f "$copiedGB GB copiados")║" -ForegroundColor White
    Write-Host "    ║  Tiempo:          $("{0,-45}" -f $elapsedStr)║" -ForegroundColor White
    Write-Host "    ║                                                                 ║" -ForegroundColor Yellow

    if ($Operation -match "CLONE|COPY") {
        Write-Host "    ║  [!] El disco DESTINO quedo INCOMPLETO                          ║" -ForegroundColor Red
        Write-Host "    ║  [!] Formatealo antes de usarlo o reinicia el clonado           ║" -ForegroundColor Red
    } elseif ($Operation -match "IMAGE|WIM") {
        Write-Host "    ║  [!] La imagen quedo INCOMPLETA                                 ║" -ForegroundColor Red
        Write-Host "    ║  [!] Eliminala y vuelve a crearla                               ║" -ForegroundColor Red
    }

    Write-Host "    ║                                                                 ║" -ForegroundColor Yellow
    Write-Host "    ║  El disco ORIGEN no fue modificado (siempre a salvo)            ║" -ForegroundColor Green
    Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
}

function Show-CancelHint {
    Write-Host "    [ESC] o [Q] para CANCELAR de forma segura" -ForegroundColor DarkGray
}

# ===============================================================================
# DOBLE CONFIRMACION PARA PROCESOS CRITICOS
# ===============================================================================

function Confirm-CriticalAction {
    <#
    .SYNOPSIS
        Solicita doble confirmacion para acciones criticas (clonar, borrar, etc.)
    .PARAMETER Action
        Descripcion de la accion (ej: "CLONAR disco 1 a disco 2")
    .PARAMETER Keyword
        Palabra clave que debe escribir el usuario (CLONAR, BORRAR, etc.)
    .PARAMETER TargetName
        Nombre del objetivo (disco, particion, etc.) para la segunda confirmacion
    .PARAMETER DangerLevel
        Nivel de peligro: "warning" (amarillo) o "danger" (rojo)
    .RETURNS
        $true si el usuario confirmo ambas veces, $false si cancelo
    #>
    param(
        [string]$Action,
        [string]$Keyword = "CONFIRMAR",
        [string]$TargetName = "",
        [ValidateSet("warning", "danger")]
        [string]$DangerLevel = "warning"
    )

    $color = if ($DangerLevel -eq "danger") { "Red" } else { "Yellow" }
    $colorDark = if ($DangerLevel -eq "danger") { "DarkRed" } else { "DarkYellow" }

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIMERA CONFIRMACION
    # ═══════════════════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor $color
    Write-Host "  ║                     CONFIRMACION REQUERIDA                        ║" -ForegroundColor $color
    Write-Host "  ╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor $color
    Write-Host "  ║                                                                   ║" -ForegroundColor $color

    # Dividir la accion en lineas si es muy larga
    $actionLines = @()
    if ($Action.Length -gt 60) {
        $words = $Action -split ' '
        $currentLine = ""
        foreach ($word in $words) {
            if (($currentLine + " " + $word).Length -gt 60) {
                $actionLines += $currentLine.Trim()
                $currentLine = $word
            } else {
                $currentLine += " $word"
            }
        }
        $actionLines += $currentLine.Trim()
    } else {
        $actionLines = @($Action)
    }

    foreach ($line in $actionLines) {
        $paddedLine = "  $line".PadRight(65)
        Write-Host "  ║ $paddedLine ║" -ForegroundColor White
    }

    Write-Host "  ║                                                                   ║" -ForegroundColor $color
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor $color
    Write-Host ""
    Write-Host "    Escribe '$Keyword' para confirmar (o ENTER para cancelar): " -NoNewline -ForegroundColor $color

    $confirm1 = Read-Host
    Write-Host ""
    Write-Host ""
    Write-Host ""
    Write-Host ""
    if ($confirm1 -ne $Keyword) {
        Write-Host ""
        Write-Host "    [X] Operacion CANCELADA" -ForegroundColor Gray
        return $false
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # SEGUNDA CONFIRMACION (mas seria)
    # ═══════════════════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║                    ¡¡ ULTIMA OPORTUNIDAD !!                       ║" -ForegroundColor Red
    Write-Host "  ╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
    Write-Host "  ║                                                                   ║" -ForegroundColor Red

    if ($Keyword -eq "CLONAR") {
        Write-Host "  ║  Esta accion BORRARA TODOS LOS DATOS del disco destino.          ║" -ForegroundColor White
        Write-Host "  ║  Esta accion es IRREVERSIBLE.                                    ║" -ForegroundColor White
    } elseif ($Keyword -eq "BORRAR") {
        Write-Host "  ║  Esta accion ELIMINARA TODOS LOS DATOS del disco.                ║" -ForegroundColor White
        Write-Host "  ║  Esta accion es IRREVERSIBLE.                                    ║" -ForegroundColor White
    } else {
        Write-Host "  ║  Esta accion puede causar PERDIDA DE DATOS.                      ║" -ForegroundColor White
        Write-Host "  ║  Asegurate de tener respaldos.                                   ║" -ForegroundColor White
    }

    if ($TargetName) {
        $targetLine = "  Objetivo: $TargetName".PadRight(65)
        Write-Host "  ║                                                                   ║" -ForegroundColor Red
        Write-Host "  ║ $targetLine ║" -ForegroundColor Yellow
    }

    Write-Host "  ║                                                                   ║" -ForegroundColor Red
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""
    Write-Host "    ¿ESTAS COMPLETAMENTE SEGURO? Escribe 'SI' para continuar: " -NoNewline -ForegroundColor Red

    $confirm2 = Read-Host
    if ($confirm2 -ne "SI") {
        Write-Host ""
        Write-Host "    [X] Operacion CANCELADA (segunda confirmacion)" -ForegroundColor Gray
        return $false
    }

    Write-Host ""
    Write-Host "    [OK] Confirmacion aceptada. Iniciando operacion..." -ForegroundColor Green
    Write-Host ""
    return $true
}

# ===============================================================================
# MENU INTERACTIVO CON FLECHAS Y HIGHLIGHT VERDE NEON
# ===============================================================================

# ===============================================================================
# SOPORTE PARA RATON EN CONSOLA
# ===============================================================================

# Cargar APIs de consola para soporte de raton (solo una vez)
if (-not ([System.Management.Automation.PSTypeName]'ConsoleMouseInput').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class ConsoleMouseInput {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadConsoleInput(IntPtr hConsoleInput, [Out] INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool PeekConsoleInput(IntPtr hConsoleInput, [Out] INPUT_RECORD[] lpBuffer, uint nLength, out uint lpNumberOfEventsRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushConsoleInputBuffer(IntPtr hConsoleInput);

    public const int STD_INPUT_HANDLE = -10;
    public const uint ENABLE_MOUSE_INPUT = 0x0010;
    public const uint ENABLE_EXTENDED_FLAGS = 0x0080;
    public const uint ENABLE_QUICK_EDIT_MODE = 0x0040;

    [StructLayout(LayoutKind.Explicit)]
    public struct INPUT_RECORD {
        [FieldOffset(0)] public ushort EventType;
        [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
        [FieldOffset(4)] public MOUSE_EVENT_RECORD MouseEvent;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KEY_EVENT_RECORD {
        public bool bKeyDown;
        public ushort wRepeatCount;
        public ushort wVirtualKeyCode;
        public ushort wVirtualScanCode;
        public char UnicodeChar;
        public uint dwControlKeyState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MOUSE_EVENT_RECORD {
        public COORD dwMousePosition;
        public uint dwButtonState;
        public uint dwControlKeyState;
        public uint dwEventFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COORD {
        public short X;
        public short Y;
    }

    public const ushort KEY_EVENT = 0x0001;
    public const ushort MOUSE_EVENT = 0x0002;
    public const uint FROM_LEFT_1ST_BUTTON_PRESSED = 0x0001;
    public const uint DOUBLE_CLICK = 0x0002;
    public const uint MOUSE_MOVED = 0x0001;  // dwEventFlags para movimiento

    private static IntPtr hInput;
    private static uint originalMode;
    private static bool initialized = false;

    public static void EnableMouseInput() {
        if (initialized) return;
        hInput = GetStdHandle(STD_INPUT_HANDLE);
        GetConsoleMode(hInput, out originalMode);
        // Habilitar raton y deshabilitar Quick Edit (que bloquea el raton)
        uint newMode = (originalMode | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE;
        SetConsoleMode(hInput, newMode);
        initialized = true;
    }

    public static void DisableMouseInput() {
        if (!initialized) return;
        SetConsoleMode(hInput, originalMode);
        initialized = false;
    }

    public static int[] ReadInput() {
        // Retorna: [tipo, dato1, dato2, dato3]
        // tipo 0 = nada, 1 = tecla, 2 = clic raton, 3 = movimiento raton (hover)
        // tecla: [1, virtualKey, char, 0]
        // clic:  [2, x, y, dobleClick]
        // hover: [3, x, y, 0]

        INPUT_RECORD[] records = new INPUT_RECORD[1];
        uint numRead;

        if (!ReadConsoleInput(hInput, records, 1, out numRead) || numRead == 0) {
            return new int[] { 0, 0, 0, 0 };
        }

        INPUT_RECORD rec = records[0];

        if (rec.EventType == KEY_EVENT && rec.KeyEvent.bKeyDown) {
            return new int[] { 1, rec.KeyEvent.wVirtualKeyCode, (int)rec.KeyEvent.UnicodeChar, 0 };
        }
        else if (rec.EventType == MOUSE_EVENT) {
            // Clic de raton (prioridad sobre hover)
            if ((rec.MouseEvent.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED) != 0) {
                int doubleClick = (rec.MouseEvent.dwEventFlags & DOUBLE_CLICK) != 0 ? 1 : 0;
                return new int[] { 2, rec.MouseEvent.dwMousePosition.X, rec.MouseEvent.dwMousePosition.Y, doubleClick };
            }
            // Movimiento de raton (hover) - solo si no hay boton y realmente se movio
            else if (rec.MouseEvent.dwButtonState == 0 && rec.MouseEvent.dwEventFlags == MOUSE_MOVED) {
                return new int[] { 3, rec.MouseEvent.dwMousePosition.X, rec.MouseEvent.dwMousePosition.Y, 0 };
            }
        }

        return new int[] { 0, 0, 0, 0 };
    }

    public static bool HasInput() {
        // Verificar si hay eventos disponibles sin bloquear
        if (!initialized) return false;
        INPUT_RECORD[] records = new INPUT_RECORD[1];
        uint numRead;
        if (PeekConsoleInput(hInput, records, 1, out numRead) && numRead > 0) {
            return true;
        }
        return false;
    }

    public static void Flush() {
        FlushConsoleInputBuffer(hInput);
    }
}
'@ -ErrorAction SilentlyContinue
}

function Show-InteractiveMenu {
    <#
    .SYNOPSIS
        Muestra un menu interactivo con navegacion por flechas y teclas de atajo
    #>
    param(
        [string]$Title = "MENU",
        [array]$Options,
        [string]$Subtitle = ""
    )

    $selectedIndex = 0
    $enabledOptions = $Options | Where-Object { -not $_.Disabled }

    # Encontrar primera opcion recomendada
    for ($i = 0; $i -lt $Options.Count; $i++) {
        if ($Options[$i].Recommended -and -not $Options[$i].Disabled) {
            $selectedIndex = $i
            break
        }
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # DISEÑO DE 6 COLUMNAS
    # | ► | [1] | LABEL | DESCRIPCION | RECOMENDADO | ◄ |
    # ═══════════════════════════════════════════════════════════════════════════
    $colArrow = 3        # Columna 1: ► (selector)
    $colKey = 5          # Columna 2: [1]
    $colLabel = 28       # Columna 3: CLONAR DISCO
    $colDesc = 26        # Columna 4: WimLib, 100-200+ MB/s
    $colRec = 13         # Columna 5: RECOMENDADO
    $colEnd = 3          # Columna 6: ◄
    # innerWidth = contenido de la fila = cols(78) + 5 separadores(│) = 83
    # totalWidth = innerWidth + 2 bordes(║) = 85
    $totalWidth = $colArrow + $colKey + $colLabel + $colDesc + $colRec + $colEnd + 7

    # Limpiar buffer de entrada (evita teclas fantasma de Start-Process)
    while (Test-KeyAvailableSafe) {
        try { $null = [Console]::ReadKey($true) } catch { break }
    }

    # Dibujar menu UNA sola vez al inicio
    Clear-Host
    Show-Logo

    $titleText = if ($Subtitle) { " $Title - $Subtitle " } else { " $Title " }
    $innerWidth = $totalWidth - 2
    $titlePadLeft = [math]::Floor(($innerWidth - $titleText.Length) / 2)
    $titlePadRight = $innerWidth - $titleText.Length - $titlePadLeft

    Write-Host "  ╔$("═" * $titlePadLeft)" -NoNewline -ForegroundColor Cyan
    Write-Host $titleText -NoNewline -ForegroundColor White
    Write-Host "$("═" * $titlePadRight)╗" -ForegroundColor Cyan
    Write-Host "  ║$(" " * $innerWidth)║" -ForegroundColor Cyan

    # Guardar posicion Y de cada opcion para redibujado parcial
    $optionYPositions = @()

    # Funcion interna para dibujar UNA opcion
    function Draw-MenuOption {
        param($idx, $opt, $selected, $innerW, $cArrow, $cKey, $cLabel, $cDesc, $cRec, $cEnd)

        $isDisabled = $opt.Disabled
        $isRecommended = $opt.Recommended
        $key = $opt.Key
        $label = if ($opt.Label) { $opt.Label } else { "" }
        $desc = if ($opt.Description) { $opt.Description } else { "" }

        $c1 = if ($selected -and -not $isDisabled) { " ► " } else { "   " }
        $c2 = if ($key -ne "-") { ("[$key]").PadRight($cKey) } else { ("").PadRight($cKey) }
        $c3 = $label.PadRight($cLabel).Substring(0, $cLabel)
        $c4 = $desc.PadRight($cDesc).Substring(0, $cDesc)
        $c5 = if ($isRecommended) { " RECOMENDADO " } else { ("").PadRight($cRec) }
        $c6 = if ($isRecommended -and $selected) { " ◄ " } else { "   " }

        if ($isDisabled) {
            $sepLine = "─" * $innerW
            Write-Host "  ╟$sepLine╢" -ForegroundColor DarkGray
        } elseif ($selected) {
            Write-Host "  ║" -NoNewline -ForegroundColor Cyan
            Write-Host "$c1│$c2│$c3│$c4│" -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
            if ($isRecommended) {
                Write-Host "$c5│$c6" -NoNewline -BackgroundColor DarkGreen -ForegroundColor Yellow
            } else {
                Write-Host "$c5│$c6" -NoNewline -BackgroundColor DarkGreen -ForegroundColor White
            }
            Write-Host "║" -ForegroundColor Cyan
        } else {
            Write-Host "  ║" -NoNewline -ForegroundColor Cyan
            Write-Host "$c1│$c2│$c3│$c4│" -NoNewline -ForegroundColor Gray
            if ($isRecommended) {
                Write-Host "$c5" -NoNewline -ForegroundColor DarkYellow
            } else {
                Write-Host "$c5" -NoNewline -ForegroundColor DarkGray
            }
            Write-Host "│$c6" -NoNewline -ForegroundColor DarkGray
            Write-Host "║" -ForegroundColor Cyan
        }
    }

    # Dibujar todas las opciones y guardar posiciones Y
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $optionYPositions += [Console]::CursorTop
        Draw-MenuOption -idx $i -opt $Options[$i] -selected ($i -eq $selectedIndex) -innerW $innerWidth -cArrow $colArrow -cKey $colKey -cLabel $colLabel -cDesc $colDesc -cRec $colRec -cEnd $colEnd
    }

    # Dibujar marco inferior (solo una vez)
    Write-Host "  ║$(" " * $innerWidth)║" -ForegroundColor Cyan
    Write-Host "  ╟$("─" * $innerWidth)╢" -ForegroundColor Cyan
    $helpText = " ↑↓ Mover   ENTER Seleccionar   [tecla] Atajo rapido"
    Write-Host "  ║$($helpText.PadRight($innerWidth))║" -ForegroundColor DarkCyan
    Write-Host "  ╚$("═" * $innerWidth)╝" -ForegroundColor Cyan
    Write-Host ""

    # Bucle de entrada - solo redibuja las opciones que cambian
    while ($true) {
        $keyInfo = Read-TeclaSafe
        $key = $keyInfo.Key
        $char = $keyInfo.KeyChar
        $prevIndex = $selectedIndex

        switch ($key) {
            "UpArrow" {
                do {
                    $selectedIndex--
                    if ($selectedIndex -lt 0) { $selectedIndex = $Options.Count - 1 }
                } while ($Options[$selectedIndex].Disabled -and $enabledOptions.Count -gt 0)
            }
            "DownArrow" {
                do {
                    $selectedIndex++
                    if ($selectedIndex -ge $Options.Count) { $selectedIndex = 0 }
                } while ($Options[$selectedIndex].Disabled -and $enabledOptions.Count -gt 0)
            }
            "Enter" {
                if (-not $Options[$selectedIndex].Disabled) {
                    return $Options[$selectedIndex].Key
                }
            }
            "Escape" { return "X" }
            default {
                $charUpper = $char.ToString().ToUpper()
                $matchedOpt = $Options | Where-Object { $_.Key -eq $charUpper -and -not $_.Disabled }
                if ($matchedOpt) { return $matchedOpt.Key }
            }
        }

        # Solo redibujar si cambio la seleccion
        if ($selectedIndex -ne $prevIndex) {
            # Redibujar opcion anterior (deseleccionar)
            [Console]::SetCursorPosition(0, $optionYPositions[$prevIndex])
            Draw-MenuOption -idx $prevIndex -opt $Options[$prevIndex] -selected $false -innerW $innerWidth -cArrow $colArrow -cKey $colKey -cLabel $colLabel -cDesc $colDesc -cRec $colRec -cEnd $colEnd

            # Redibujar opcion nueva (seleccionar)
            [Console]::SetCursorPosition(0, $optionYPositions[$selectedIndex])
            Draw-MenuOption -idx $selectedIndex -opt $Options[$selectedIndex] -selected $true -innerW $innerWidth -cArrow $colArrow -cKey $colKey -cLabel $colLabel -cDesc $colDesc -cRec $colRec -cEnd $colEnd
        }
    }
}

# Menu interactivo - redibujado parcial sin parpadeo

# Funcion para seleccionar disco con flechas - FLUIDO SIN PARPADEO
function Select-DiskInteractive {
    param(
        [string]$Title = "SELECCIONAR DISCO",
        [string]$Prompt = "Selecciona un disco",
        [switch]$ExcludeWindows
    )

    $disks = Get-DiskList -Silent
    if (-not $disks -or $disks.Count -eq 0) {
        Write-Host "  [ERROR] No se detectaron discos" -ForegroundColor Red
        Read-Host "  ENTER para continuar"
        return $null
    }

    $selectedIndex = 0

    # Encontrar primera opcion no-Windows si ExcludeWindows
    if ($ExcludeWindows) {
        for ($i = 0; $i -lt $disks.Count; $i++) {
            if (-not $disks[$i].TieneWindows) {
                $selectedIndex = $i
                break
            }
        }
    }

    # Funcion interna para dibujar UN disco
    function Draw-DiskEntry {
        param($d, $selected, $disabled)

        $icono = switch ($d.Type) { "SSD" { "[SSD]" } "HDD" { "[HDD]" } "USB" { "[USB]" } default { "[---]" } }
        $winTag = if ($d.EsDiscoSistemaActual) { " *** NO TOCAR ***" } elseif ($d.TieneWindows) { " ** WINDOWS **" } else { "" }
        $blTag = if ($d.TieneBitLocker) { " [BITLOCKER]" } else { "" }
        $dynTag = if ($d.EsDinamico) { " [DINAMICO]" } else { "" }
        $hwCorto = if ($d.HWName.Length -gt 30) { $d.HWName.Substring(0,27) + "..." } else { $d.HWName }

        $colorDisco = if ($disabled) { "DarkGray" }
                      elseif ($d.EsDiscoSistemaActual -or $d.TieneBitLocker -or $d.EsDinamico) { "Red" }
                      elseif ($d.TieneWindows) { "Red" }
                      else { "White" }
        $borderColor = if ($selected -and -not $disabled) { "Green" } else { "DarkGray" }
        $headerText = "[$($d.Index)] $icono $hwCorto ($($d.SizeGB) GB)$winTag$blTag$dynTag"
        if ($disabled) { $headerText += " [NO DISPONIBLE]" }
        $padding = 69 - $headerText.Length
        $padStr = if ($padding -gt 0) { " " * $padding } else { "" }

        if ($selected -and -not $disabled) {
            Write-Host "  ► ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Green
            Write-Host "    │ $headerText$padStr │" -ForegroundColor Green
            Write-Host "    ├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor Green
        } else {
            Write-Host "    ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor $borderColor
            Write-Host "    │ " -NoNewline -ForegroundColor $borderColor
            Write-Host $headerText -NoNewline -ForegroundColor $colorDisco
            Write-Host "$padStr │" -ForegroundColor $borderColor
            Write-Host "    ├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor $borderColor
        }

        if ($d.Volumenes.Count -eq 0) {
            if ($selected -and -not $disabled) {
                Write-Host "    │   (sin particiones visibles)                                       │" -ForegroundColor Green
            } else {
                Write-Host "    │   (sin particiones visibles)                                       │" -ForegroundColor $borderColor
            }
        } else {
            foreach ($v in $d.Volumenes) {
                $pctUsado = if ($v.TotalGB -gt 0) { [math]::Round((($v.TotalGB - $v.LibreGB) / $v.TotalGB) * 10) } else { 0 }
                $barra = ("█" * $pctUsado) + ("░" * (10 - $pctUsado))
                $nombreCorto = if ($v.Nombre.Length -gt 15) { $v.Nombre.Substring(0,12) + "..." } else { $v.Nombre }
                $linea = "    $($v.Letra) $nombreCorto".PadRight(25) + "[$barra] $($v.LibreGB) GB libres de $($v.TotalGB) GB"
                $pad2 = 69 - $linea.Length
                $padStr2 = if ($pad2 -gt 0) { " " * $pad2 } else { "" }

                if ($selected -and -not $disabled) {
                    Write-Host "    │ $linea$padStr2 │" -ForegroundColor Green
                } else {
                    $colorVol = if ($v.EsWindows) { "Yellow" } elseif ($v.BitLocker) { "Red" } else { "Gray" }
                    Write-Host "    │ " -NoNewline -ForegroundColor $borderColor
                    Write-Host $linea -NoNewline -ForegroundColor $colorVol
                    Write-Host "$padStr2 │" -ForegroundColor $borderColor
                }
            }
        }

        if ($selected -and -not $disabled) {
            Write-Host "    └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Green
        } else {
            Write-Host "    └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor $borderColor
        }
        Write-Host ""
    }

    # Dibujar pantalla inicial UNA vez
    Clear-Host
    Show-Logo -Subtitulo $Title
    Write-Host "    $Prompt" -ForegroundColor Gray
    Write-Host ""

    # Guardar posiciones Y y alturas de cada disco
    $diskPositions = @()
    for ($i = 0; $i -lt $disks.Count; $i++) {
        $startY = [Console]::CursorTop
        $d = $disks[$i]
        $isDisabled = ($ExcludeWindows -and $d.TieneWindows)
        Draw-DiskEntry -d $d -selected ($i -eq $selectedIndex) -disabled $isDisabled
        $endY = [Console]::CursorTop
        $diskPositions += @{ StartY = $startY; Height = $endY - $startY; Disk = $d; Disabled = $isDisabled }
    }

    # Opcion Volver
    $volverY = [Console]::CursorTop
    if ($selectedIndex -eq $disks.Count) {
        Write-Host "  ► [V] Volver al menu" -ForegroundColor Green
    } else {
        Write-Host "    [V] Volver al menu" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "    ─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "    ↑↓ Mover   ENTER Seleccionar   [numero] Atajo rapido" -ForegroundColor DarkCyan
    Write-Host ""

    # Bucle de entrada - redibujado parcial
    while ($true) {
        $keyInfo = Read-TeclaSafe
        $key = $keyInfo.Key
        $char = $keyInfo.KeyChar
        $prevIndex = $selectedIndex

        switch ($key) {
            "UpArrow" {
                do {
                    $selectedIndex--
                    if ($selectedIndex -lt 0) { $selectedIndex = $disks.Count }
                } while ($selectedIndex -lt $disks.Count -and $ExcludeWindows -and $disks[$selectedIndex].TieneWindows)
            }
            "DownArrow" {
                do {
                    $selectedIndex++
                    if ($selectedIndex -gt $disks.Count) { $selectedIndex = 0 }
                } while ($selectedIndex -lt $disks.Count -and $ExcludeWindows -and $disks[$selectedIndex].TieneWindows)
            }
            "Enter" {
                if ($selectedIndex -eq $disks.Count) { return $null }
                $sel = $disks[$selectedIndex]
                if (-not ($ExcludeWindows -and $sel.TieneWindows)) { return $sel }
            }
            "Escape" { return $null }
            default {
                $charUpper = $char.ToString().ToUpper()
                if ($charUpper -eq "V") { return $null }
                if ($charUpper -match "^\d+$") {
                    $idx = [int]$charUpper
                    $match = $disks | Where-Object { $_.Index -eq $idx }
                    if ($match -and -not ($ExcludeWindows -and $match.TieneWindows)) { return $match }
                }
            }
        }

        # Solo redibujar si cambio la seleccion
        if ($selectedIndex -ne $prevIndex) {
            # Redibujar elemento anterior
            if ($prevIndex -lt $disks.Count) {
                $pos = $diskPositions[$prevIndex]
                [Console]::SetCursorPosition(0, $pos.StartY)
                Draw-DiskEntry -d $pos.Disk -selected $false -disabled $pos.Disabled
            } else {
                [Console]::SetCursorPosition(0, $volverY)
                Write-Host "    [V] Volver al menu                                                    " -ForegroundColor Gray
            }

            # Redibujar elemento nuevo
            if ($selectedIndex -lt $disks.Count) {
                $pos = $diskPositions[$selectedIndex]
                [Console]::SetCursorPosition(0, $pos.StartY)
                Draw-DiskEntry -d $pos.Disk -selected $true -disabled $pos.Disabled
            } else {
                [Console]::SetCursorPosition(0, $volverY)
                Write-Host "  ► [V] Volver al menu                                                    " -ForegroundColor Green
            }
        }
    }
}

# ===============================================================================
# FUNCIONES AUXILIARES
# ===============================================================================

# Ocultar unidad de Explorer y suprimir popups de formateo
function Hide-DriveFromExplorer {
    param([char]$DriveLetter)

    # Calcular bitmask para NoDrives (A=1, B=2, C=4, D=8, etc.)
    $bitPosition = [int][char]$DriveLetter - [int][char]'A'
    $bitMask = [math]::Pow(2, $bitPosition)

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # Crear clave si no existe
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Obtener valor actual
    $currentValue = Get-ItemProperty -Path $regPath -Name "NoDrives" -ErrorAction SilentlyContinue
    if ($currentValue) {
        $newValue = [int]$currentValue.NoDrives -bor [int]$bitMask
    } else {
        $newValue = [int]$bitMask
    }

    Set-ItemProperty -Path $regPath -Name "NoDrives" -Value $newValue -Type DWord -ErrorAction SilentlyContinue
}

function Show-DriveInExplorer {
    param([char]$DriveLetter)

    $bitPosition = [int][char]$DriveLetter - [int][char]'A'
    $bitMask = [math]::Pow(2, $bitPosition)

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    $currentValue = Get-ItemProperty -Path $regPath -Name "NoDrives" -ErrorAction SilentlyContinue
    if ($currentValue) {
        $newValue = [int]$currentValue.NoDrives -band (-bnot [int]$bitMask)
        if ($newValue -eq 0) {
            Remove-ItemProperty -Path $regPath -Name "NoDrives" -ErrorAction SilentlyContinue
        } else {
            Set-ItemProperty -Path $regPath -Name "NoDrives" -Value $newValue -Type DWord -ErrorAction SilentlyContinue
        }
    }
}

function Disable-FormatPopups {
    # Detener servicio de detección de hardware (evita popups de formateo)
    Stop-Service -Name "ShellHWDetection" -Force -ErrorAction SilentlyContinue
}

function Enable-FormatPopups {
    # Restaurar servicio
    Start-Service -Name "ShellHWDetection" -ErrorAction SilentlyContinue
}

# =============================================================================
# PROTECCION ANTI-LISTILLOS DURANTE CLONADO
# =============================================================================
# Casos prevenidos:
#   1. Usuario abre Explorer y borra/mueve archivos del disco mientras clona
#   2. Usuario abre CMD/PowerShell y ejecuta comandos en las unidades
#   3. Usuario abre Administrador de Discos y formatea/elimina particiones
#   4. Usuario intenta "Expulsar" el disco USB desde la bandeja
#   5. Usuario hace doble clic en unidad y Windows pide formatear
#   6. Usuario arrastra archivos al disco destino mientras se clona
#   7. Antivirus escanea el disco destino y bloquea archivos
#   8. Windows Indexer intenta indexar el disco nuevo
#   9. Usuario desenchufa el cable USB "porque tarda mucho"
#  10. Usuario cierra la ventana de PowerShell pensando que se colgó
# =============================================================================

$script:ProtectedDrives = @()
$script:OriginalNoDrives = $null
$script:DiskmgmtBlocked = $false

function Protect-CloneDrives {
    <#
    .SYNOPSIS
        Oculta y bloquea las unidades involucradas en el clonado
    .PARAMETER DriveLetters
        Array de letras de unidad a proteger (ej: @('J','K','L'))
    #>
    param([string[]]$DriveLetters)

    if (-not $DriveLetters -or $DriveLetters.Count -eq 0) { return }

    Write-Host ""
    Write-Host "  [PROTECCION] Bloqueando acceso a unidades durante clonado..." -ForegroundColor Yellow

    $script:ProtectedDrives = $DriveLetters

    # ─────────────────────────────────────────────────────────────────────────
    # 1. OCULTAR EN WINDOWS EXPLORER (NoDrives)
    # ─────────────────────────────────────────────────────────────────────────
    # NoDrives es un bitmask: A=1, B=2, C=4, D=8, E=16, F=32...
    # Para ocultar J (9) = 2^9 = 512, K (10) = 2^10 = 1024, etc.
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }

        # Guardar valor original
        $script:OriginalNoDrives = (Get-ItemProperty -Path $regPath -Name "NoDrives" -ErrorAction SilentlyContinue).NoDrives

        # Calcular bitmask para las unidades a ocultar
        $mask = 0
        foreach ($letter in $DriveLetters) {
            $index = [int][char]$letter.ToUpper() - [int][char]'A'
            $mask = $mask -bor [math]::Pow(2, $index)
        }

        # Si habia valor previo, combinarlo
        if ($script:OriginalNoDrives) {
            $mask = $mask -bor $script:OriginalNoDrives
        }

        Set-ItemProperty -Path $regPath -Name "NoDrives" -Value ([int]$mask) -Type DWord -Force
        Write-Host "    [OK] Unidades ocultas en Explorer: $($DriveLetters -join ', ')" -ForegroundColor Green
    } catch {
        Write-Host "    [!] No se pudo ocultar en Explorer: $_" -ForegroundColor DarkYellow
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 2. BLOQUEAR ACCESO (NoViewOnDrive) - Previene abrir aunque sepa la ruta
    # ─────────────────────────────────────────────────────────────────────────
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        Set-ItemProperty -Path $regPath -Name "NoViewOnDrive" -Value ([int]$mask) -Type DWord -Force
        Write-Host "    [OK] Acceso bloqueado a: $($DriveLetters -join ', ')" -ForegroundColor Green
    } catch {
        Write-Host "    [!] No se pudo bloquear acceso: $_" -ForegroundColor DarkYellow
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 3. CERRAR ADMINISTRADOR DE DISCOS SI ESTA ABIERTO
    # ─────────────────────────────────────────────────────────────────────────
    try {
        $diskmgmt = Get-Process -Name "mmc" -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -like "*Administraci*disco*" -or $_.MainWindowTitle -like "*Disk Management*"
        }
        if ($diskmgmt) {
            $diskmgmt | Stop-Process -Force -ErrorAction SilentlyContinue
            Write-Host "    [OK] Administrador de discos cerrado" -ForegroundColor Green
        }
    } catch {}

    # ─────────────────────────────────────────────────────────────────────────
    # 4. DETENER SERVICIOS QUE PUEDEN INTERFERIR
    # ─────────────────────────────────────────────────────────────────────────
    $servicesToStop = @(
        "WSearch",          # Windows Search (indexador)
        "WMPNetworkSvc"     # Windows Media Player Network Sharing
    )
    foreach ($svc in $servicesToStop) {
        try {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq "Running") {
                Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                Write-Host "    [OK] Servicio $svc detenido" -ForegroundColor DarkGray
            }
        } catch {}
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 5. REFRESCAR EXPLORER PARA APLICAR CAMBIOS
    # ─────────────────────────────────────────────────────────────────────────
    Refresh-Explorer -Silent

    Write-Host "  [PROTECCION] Unidades protegidas. El usuario no puede interferir." -ForegroundColor Green
    Write-Host ""
}

function Unprotect-CloneDrives {
    <#
    .SYNOPSIS
        Restaura el acceso a las unidades después del clonado
    #>

    Write-Host ""
    Write-Host "  [RESTAURAR] Desbloqueando unidades..." -ForegroundColor Cyan

    # ─────────────────────────────────────────────────────────────────────────
    # 1. RESTAURAR NoDrives Y NoViewOnDrive
    # ─────────────────────────────────────────────────────────────────────────
    try {
        $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

        if ($script:OriginalNoDrives) {
            Set-ItemProperty -Path $regPath -Name "NoDrives" -Value $script:OriginalNoDrives -Type DWord -Force
        } else {
            Remove-ItemProperty -Path $regPath -Name "NoDrives" -ErrorAction SilentlyContinue
        }
        Remove-ItemProperty -Path $regPath -Name "NoViewOnDrive" -ErrorAction SilentlyContinue

        Write-Host "    [OK] Unidades visibles de nuevo" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Error restaurando registro: $_" -ForegroundColor Yellow
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 2. REINICIAR SERVICIOS
    # ─────────────────────────────────────────────────────────────────────────
    $servicesToStart = @("WSearch")
    foreach ($svc in $servicesToStart) {
        try {
            Start-Service -Name $svc -ErrorAction SilentlyContinue
        } catch {}
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 3. REFRESCAR EXPLORER
    # ─────────────────────────────────────────────────────────────────────────
    Refresh-Explorer

    # Limpiar variables
    $script:ProtectedDrives = @()
    $script:OriginalNoDrives = $null

    Write-Host "  [RESTAURAR] Unidades accesibles. Todo normal." -ForegroundColor Green
    Write-Host ""
}

function Refresh-Explorer {
    <#
    .SYNOPSIS
        Refresca Windows Explorer para aplicar cambios en unidades
    #>
    param([switch]$Silent)

    try {
        # Metodo 1: Enviar mensaje de broadcast para refrescar
        $code = @'
        [DllImport("shell32.dll")]
        public static extern void SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
'@
        $shell = Add-Type -MemberDefinition $code -Name "Shell32Refresh" -Namespace "Win32" -PassThru -ErrorAction SilentlyContinue
        if ($shell) {
            # SHCNE_ASSOCCHANGED = 0x08000000, SHCNF_IDLIST = 0
            $shell::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)
        }

        # Metodo 2: Refrescar iconos del escritorio
        $explorerProcesses = Get-Process -Name "explorer" -ErrorAction SilentlyContinue
        if ($explorerProcesses) {
            # No matamos explorer, solo refrescamos
            $wshell = New-Object -ComObject WScript.Shell
            $wshell.SendKeys("{F5}")
        }

        if (-not $Silent) {
            Write-Host "    [OK] Explorer refrescado" -ForegroundColor Green
        }
    } catch {
        if (-not $Silent) {
            Write-Host "    [!] No se pudo refrescar Explorer" -ForegroundColor DarkYellow
        }
    }
}

function Show-Logo {
    param([string]$Subtitulo = "")

    Clear-Host
    Write-Host ""
    # Logo ASCII - ancho total ~89 caracteres
    Write-Host "     ██████╗██╗      ██████╗ ███╗   ██╗ █████╗ ██████╗ ██╗███████╗ ██████╗ ██████╗ ███████╗" -ForegroundColor Cyan
    Write-Host "    ██╔════╝██║     ██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██║██╔════╝██╔════╝██╔═══██╗██╔════╝" -ForegroundColor Cyan
    Write-Host "    ██║     ██║     ██║   ██║██╔██╗ ██║███████║██║  ██║██║███████╗██║     ██║   ██║███████╗" -ForegroundColor Cyan
    Write-Host "    ██║     ██║     ██║   ██║██║╚██╗██║██╔══██║██║  ██║██║╚════██║██║     ██║   ██║╚════██║" -ForegroundColor Cyan
    Write-Host "    ╚██████╗███████╗╚██████╔╝██║ ╚████║██║  ██║██████╔╝██║███████║╚██████╗╚██████╔╝███████║" -ForegroundColor Cyan
    Write-Host "    ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝" -ForegroundColor Cyan
    # Header alineado - todos terminan en columna 89
    Write-Host "    SIMPLE · FUNCIONAL                                                    ARCAMIA-MEMMEM" -ForegroundColor DarkGray
    Write-Host "    Clona tu DISCO con UN CLICK                   www.discocloner.com · www.clonadiscos.com" -ForegroundColor DarkGray
    Write-Host "    Optimiza tu PC con UN CLICK                                        www.fregonator.com" -ForegroundColor DarkGray
    Write-Host "    " -NoNewline
    Write-Host "COSTA DA MORTE" -NoNewline -ForegroundColor Cyan
    Write-Host " # " -NoNewline -ForegroundColor DarkGray
    Write-Host "DEATH COAST" -NoNewline -ForegroundColor Cyan
    Write-Host "                                  www.costa-da-morte.com" -ForegroundColor Cyan
    Write-Host ""

    if ($Subtitulo) {
        Write-Host ""
        Write-Host "  $Subtitulo" -ForegroundColor Yellow
    }
    Write-Host ""
}

function Show-NalaSplash {
    # Splash screen con Nala y arcoiris estilo COCO (puente de petalos)
    Clear-Host

    # Colores arcoiris estilo COCO (calidos -> frios)
    $cocoColors = @(
        "DarkYellow",   # Naranja cempasuchil
        "Yellow",       # Amarillo dorado
        "Magenta",      # Rosa mexicano
        "Red",          # Rojo
        "DarkMagenta",  # Morado
        "Blue",         # Azul
        "Cyan",         # Cyan
        "Green"         # Verde
    )

    # ASCII art de Nala
    $nalaArt = @(
        "",
        "",
        "                   ......                  .............  ",
        "                .....;;...                ................  ",
        "             .......;;;;;/mmmmmmmmmmmmmm\/..................  ",
        "           ........;;;mmmmmmmmmmmmmmmmmmm.....................  ",
        "         .........;;m/;;;;\mmmmmm/;;;;;\m......................  ",
        "      ..........;;;m;;mmmm;;mmmm;;mmmmm;;m......................  ",
        "    ..........;;;;;mmmnnnmmmmmmmmmmnnnmmmm\......................  ",
        "    .........  ;;;;;n/#####\nmmmmn/#####\nmm\...................  ",
        "    .......     ;;;;n##...##nmmmmn##...##nmmmm\.................  ",
        "    ....        ;;;n#..o.|nmmmmn#..o..#nmmmmm,l.............  ",
        "     ..          mmmn\.../nmmmmmmn\.../nmmmm,m,lll.......  ",
        "              /mmmmmmmmmmmmmmmmmmmmmmmmmmm,mmmm,llll..  ",
        "          /mmmmmmmmmmmmmmmmmmmmmmm\nmmmn/mmmmmmm,lll/  ",
        "       /mmmmm/..........\mmmmmmmmmmnnmnnmmmmmmmmm,ll  ",
        "      mmmmmm|..o....o..|mmmmmmmmmmmmmmmmmmmmmmmm,ll  ",
        "      \mmmmmmm\......./mmmmmmmmmmmmmmmmmmmmmmmmm,llo  ",
        "        \mmmmmmm\.../mmmmmmmmmmmmmmmmmmmmmmmmmm,lloo  ",
        "          \mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm,ll/oooo  ",
        "             \mmmmmmmmmmll..;;;.;;;;;;/mmm,lll/oooooo\  ",
        "                       ll..;;;.;;;;;;/llllll/ooooooooo\  ",
        "                       ll.;;;.;;;;;/.llll/oooooooooooo\  ",
        "                       ll;;;.;;;;;;..ll/ooooooooooooooo\  ",
        "                       \;;;;.;;;;;..ll/oooooooooooooooo\  ",
        "                     ;;;;;;;;;;;;..ll|oooooooooooooooo  ",
        "                    ;;;;;;.;;;;;;.ll/ooooooooooooooooooo\  ",
        "                    ;;;;;.;;;;;;;ll/ooooooooooooo.....oooo  ",
        "                     \;;;.;;;;;;/oooooooooooo.....oooooooo\  ",
        "                      \;;;.;;;;/ooooooooo.....ooooooooooooo  ",
        "                        \;;;;/ooooooo.....oooooooooooooooo\  ",
        "                        |o\;/oooo.....ooooooooooooooooooooo\  ",
        "                        oooooo....ooooooooooooooooooooooooo\  ",
        "                       oooo....oooooooooooooooooooooooooooo\  ",
        "                      ___.ooooooooooooooooooooooooooooooooooo\  ",
        "                     /XXX\oooooooooooooooooooooooooooooooooooo\ ",
        "                     |XXX|ooooo.ooooooooooooooooooooooooooooooo\  ",
        "                   /oo\X/oooo..ooooooooooooooooooooooooooooooooo\  ",
        "                 /ooooooo..ooooo..oooooooooooooooooooooooooooooo\ ",
        "               /oooooooooooooooooooooooooooooooooooooooooooooooooo\ ",
        "",
        "                                    NALA  /  Annie  /  Todos  /  ...",
        ""
    )

    # Mostrar con barrido de colores
    $colorIndex = 0
    foreach ($line in $nalaArt) {
        $color = $cocoColors[$colorIndex % $cocoColors.Count]
        Write-Host $line -ForegroundColor $color
        $colorIndex++
        Start-Sleep -Milliseconds 35
    }

    # Sonidos finales con WAV
    Start-Sleep -Milliseconds 100

    # Acorde de bienvenida
    try {
        $chordPlayer = New-Object System.Media.SoundPlayer "C:\Windows\Media\chord.wav"
        $chordPlayer.PlaySync()
    } catch {}

    Start-Sleep -Milliseconds 200

    # Ladrido de Nala! "Guau guau!"
    $barkPath = "$PSScriptRoot\sounds\bark.wav"
    if (Test-Path $barkPath) {
        try {
            $barkPlayer = New-Object System.Media.SoundPlayer $barkPath
            $barkPlayer.PlaySync()
            Start-Sleep -Milliseconds 100
            $barkPlayer.PlaySync()  # Doble ladrido
        } catch {}
    }

    # Mensaje de bienvenida
    Write-Host ""
    Write-Host "                         Cargando CLONADISCOS v2.0..." -ForegroundColor Cyan
    Write-Host ""
    Start-Sleep -Milliseconds 300

    # Box de colaboracion con Claude Code + Costa da Morte
    Write-Host "        ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor DarkGray
    Write-Host "        ║       " -NoNewline -ForegroundColor DarkGray
    Write-Host "Desarrollado en colaboracion con " -NoNewline -ForegroundColor Gray
    Write-Host "CLAUDE CODE" -NoNewline -ForegroundColor Magenta
    Write-Host " (" -NoNewline -ForegroundColor Gray
    Write-Host "ANTHROPIC" -NoNewline -ForegroundColor Cyan
    Write-Host ")" -NoNewline -ForegroundColor Gray
    Write-Host "    ║" -ForegroundColor DarkGray
    Write-Host "        ╠═══════════════════════════════════════════════════════════════╣" -ForegroundColor DarkGray
    Write-Host "        ║     " -NoNewline -ForegroundColor DarkGray
    Write-Host "COSTA DA MORTE" -NoNewline -ForegroundColor Cyan
    Write-Host " # " -NoNewline -ForegroundColor DarkGray
    Write-Host "DEATH COAST" -NoNewline -ForegroundColor Cyan
    Write-Host "     " -NoNewline -ForegroundColor DarkGray
    Write-Host "www.costa-da-morte.com" -NoNewline -ForegroundColor Cyan
    Write-Host "     ║" -ForegroundColor DarkGray
    Write-Host "        ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 800
}

function Show-GlobalProgress {
    param(
        [int]$CurrentPart,
        [int]$TotalParts,
        [string]$PartitionName,
        [double]$TotalGB,
        [double]$CopiedGB,
        [datetime]$StartTime
    )

    $overallPct = if ($TotalGB -gt 0) {
        [math]::Min(100, [math]::Round(($CopiedGB / $TotalGB) * 100))
    } else { 0 }

    $elapsed = (Get-Date) - $StartTime
    $elapsedStr = "{0:hh\:mm\:ss}" -f $elapsed

    # Estimar tiempo restante
    if ($CopiedGB -gt 0 -and $elapsed.TotalSeconds -gt 0) {
        $remainingGB = $TotalGB - $CopiedGB
        $speedGBs = $CopiedGB / $elapsed.TotalSeconds
        $remainingSecs = if ($speedGBs -gt 0) { $remainingGB / $speedGBs } else { 0 }
        $remainingStr = "{0:hh\:mm\:ss}" -f [TimeSpan]::FromSeconds($remainingSecs)
    } else {
        $remainingStr = "--:--:--"
    }

    $barWidth = 50
    $filled = [math]::Floor(($overallPct / 100) * $barWidth)
    $empty = $barWidth - $filled
    $bar = ("█" * $filled) + ("░" * $empty)

    Write-Host "`r  [$bar] $overallPct% | $([math]::Round($CopiedGB,1))/$([math]::Round($TotalGB,1)) GB | $elapsedStr < $remainingStr | Particion $CurrentPart/$TotalParts" -NoNewline -ForegroundColor Cyan
}

function Test-AdminRequired {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  [ERROR] Este modulo requiere permisos de ADMINISTRADOR" -ForegroundColor Red
        Write-Host "  Por favor, ejecuta ARCAMIA-MEMMEM como administrador." -ForegroundColor Yellow
        Write-Host ""
        return $false
    }
    return $true
}

function Test-DiskConnected {
    param([int]$DiskNumber, [string]$Nombre = "disco")
    $disk = Get-Disk -Number $DiskNumber -ErrorAction SilentlyContinue
    if (-not $disk -or $disk.OperationalStatus -ne "Online") {
        Write-Host ""
        Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║  [ERROR] $($Nombre.ToUpper()) DESCONECTADO!                                  ║" -ForegroundColor Red
        Write-Host "  ║  El disco $DiskNumber ya no esta disponible.                         ║" -ForegroundColor Red
        Write-Host "  ║  Reconecta el disco e intenta de nuevo.                       ║" -ForegroundColor Red
        Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        return $false
    }
    return $true
}

# ===============================================================================
# HEALTH CHECK DE DISCO - Detecta problemas antes de clonar
# ===============================================================================

function Get-DiskHealthCheck {
    param(
        [int]$DiskNumber,
        [switch]$ShowDetails
    )

    $health = @{
        DiskNumber = $DiskNumber
        Score = 100
        Status = "SALUDABLE"
        Problemas = @()
        Advertencias = @()
        SMART = @{}
    }

    try {
        $disk = Get-Disk -Number $DiskNumber -ErrorAction Stop
        $physDisk = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskNumber -or $_.FriendlyName -eq $disk.FriendlyName } | Select-Object -First 1

        # 1. ESTADO OPERACIONAL
        if ($disk.OperationalStatus -ne "Online") {
            $health.Problemas += "Disco OFFLINE"
            $health.Score -= 50
        }
        if ($disk.HealthStatus -ne "Healthy") {
            $health.Problemas += "Estado: $($disk.HealthStatus)"
            $health.Score -= 30
        }

        # 2. SMART DATA (si disponible)
        if ($physDisk) {
            $reliability = Get-StorageReliabilityCounter -PhysicalDisk $physDisk -ErrorAction SilentlyContinue

            if ($reliability) {
                $health.SMART = @{
                    Temperature = $reliability.Temperature
                    ReadErrors = $reliability.ReadErrorsTotal
                    WriteErrors = $reliability.WriteErrorsTotal
                    Wear = $reliability.Wear
                    PowerOnHours = $reliability.PowerOnHours
                }

                # Temperatura alta (>50°C)
                if ($reliability.Temperature -and $reliability.Temperature -gt 50) {
                    $health.Advertencias += "Temperatura alta: $($reliability.Temperature)C"
                    $health.Score -= 10
                }

                # Errores de lectura
                if ($reliability.ReadErrorsTotal -and $reliability.ReadErrorsTotal -gt 0) {
                    $health.Problemas += "Errores de lectura: $($reliability.ReadErrorsTotal)"
                    $health.Score -= 20
                }

                # Errores de escritura
                if ($reliability.WriteErrorsTotal -and $reliability.WriteErrorsTotal -gt 0) {
                    $health.Problemas += "Errores de escritura: $($reliability.WriteErrorsTotal)"
                    $health.Score -= 20
                }

                # Desgaste SSD (>80%)
                if ($reliability.Wear -and $reliability.Wear -gt 80) {
                    $health.Problemas += "SSD desgastado: $($reliability.Wear)%"
                    $health.Score -= 30
                }

                # Muchas horas de uso (>40000h = ~4.5 años 24/7)
                if ($reliability.PowerOnHours -and $reliability.PowerOnHours -gt 40000) {
                    $health.Advertencias += "Disco veterano: $([math]::Round($reliability.PowerOnHours/24)) dias encendido"
                    $health.Score -= 5
                }
            }

            # MediaType y estado
            if ($physDisk.MediaType -eq "SSD" -and $physDisk.HealthStatus -ne "Healthy") {
                $health.Problemas += "SSD reporta mal estado"
                $health.Score -= 25
            }
        }

        # 3. COMPRESION NTFS EN PARTICIONES DEL SISTEMA
        $particiones = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter }
        foreach ($part in $particiones) {
            $letra = "$($part.DriveLetter):"

            # Verificar si es disco de Windows
            if (Test-Path "$letra\Windows\System32") {
                # Verificar compresion en archivos criticos
                $archivosCriticos = @(
                    "$letra\Windows\System32\ntoskrnl.exe"
                    "$letra\Windows\System32\config\SYSTEM"
                    "$letra\bootmgr"
                )

                foreach ($archivo in $archivosCriticos) {
                    if (Test-Path $archivo) {
                        $item = Get-Item $archivo -Force -ErrorAction SilentlyContinue
                        if ($item -and ($item.Attributes -band [System.IO.FileAttributes]::Compressed)) {
                            $health.Problemas += "ARCHIVO CRITICO COMPRIMIDO: $archivo"
                            $health.Score -= 15
                        }
                    }
                }

                # Verificar si C:\ tiene compresion activada a nivel de carpeta
                $rootItem = Get-Item "$letra\" -Force -ErrorAction SilentlyContinue
                if ($rootItem -and ($rootItem.Attributes -band [System.IO.FileAttributes]::Compressed)) {
                    $health.Advertencias += "Compresion NTFS activa en $letra (puede causar BSOD)"
                    $health.Score -= 10
                }
            }
        }

        # 4. Determinar estado final
        if ($health.Score -lt 0) { $health.Score = 0 }

        if ($health.Score -ge 80) {
            $health.Status = "SALUDABLE"
        } elseif ($health.Score -ge 50) {
            $health.Status = "ADVERTENCIA"
        } else {
            $health.Status = "CRITICO"
        }

    } catch {
        $health.Problemas += "Error al analizar: $_"
        $health.Score = 0
        $health.Status = "ERROR"
    }

    return $health
}

function Show-DiskHealthCheck {
    param([int]$DiskNumber)

    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                    HEALTH CHECK - DISCO $DiskNumber                              ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Analizando disco..." -ForegroundColor Gray

    $health = Get-DiskHealthCheck -DiskNumber $DiskNumber -ShowDetails

    # Score visual
    $scoreColor = if ($health.Score -ge 80) { "Green" } elseif ($health.Score -ge 50) { "Yellow" } else { "Red" }
    $statusColor = $scoreColor

    $barWidth = 30
    $filled = [math]::Floor(($health.Score / 100) * $barWidth)
    $empty = $barWidth - $filled
    $bar = ("█" * $filled) + ("░" * $empty)

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  PUNTUACION: " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$bar] $($health.Score)%" -NoNewline -ForegroundColor $scoreColor
    $pad = 24 - "$($health.Score)%".Length
    Write-Host (" " * $pad) -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
    Write-Host "  │  ESTADO:     " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($health.Status)" -NoNewline -ForegroundColor $statusColor
    $pad2 = 55 - $health.Status.Length
    Write-Host (" " * $pad2) -NoNewline
    Write-Host "│" -ForegroundColor DarkGray
    Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray

    # SMART Data
    if ($health.SMART.Count -gt 0) {
        Write-Host ""
        Write-Host "  DATOS SMART:" -ForegroundColor Cyan
        if ($health.SMART.Temperature) {
            $tempColor = if ($health.SMART.Temperature -gt 50) { "Yellow" } else { "Gray" }
            Write-Host "    Temperatura:    $($health.SMART.Temperature)°C" -ForegroundColor $tempColor
        }
        if ($health.SMART.PowerOnHours) {
            Write-Host "    Horas encendido: $($health.SMART.PowerOnHours)h ($([math]::Round($health.SMART.PowerOnHours/24)) dias)" -ForegroundColor Gray
        }
        if ($health.SMART.Wear) {
            $wearColor = if ($health.SMART.Wear -gt 80) { "Red" } elseif ($health.SMART.Wear -gt 50) { "Yellow" } else { "Gray" }
            Write-Host "    Desgaste SSD:   $($health.SMART.Wear)%" -ForegroundColor $wearColor
        }
        if ($health.SMART.ReadErrors) { Write-Host "    Errores lectura: $($health.SMART.ReadErrors)" -ForegroundColor Red }
        if ($health.SMART.WriteErrors) { Write-Host "    Errores escrit.: $($health.SMART.WriteErrors)" -ForegroundColor Red }
    }

    # Problemas
    if ($health.Problemas.Count -gt 0) {
        Write-Host ""
        Write-Host "  PROBLEMAS DETECTADOS:" -ForegroundColor Red
        foreach ($prob in $health.Problemas) {
            Write-Host "    [X] $prob" -ForegroundColor Red
        }
    }

    # Advertencias
    if ($health.Advertencias.Count -gt 0) {
        Write-Host ""
        Write-Host "  ADVERTENCIAS:" -ForegroundColor Red
        foreach ($adv in $health.Advertencias) {
            Write-Host "    [!] $adv" -ForegroundColor Red
        }
    }

    # Todo OK
    if ($health.Problemas.Count -eq 0 -and $health.Advertencias.Count -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No se detectaron problemas. Disco listo para clonar." -ForegroundColor Green
    }

    Write-Host ""
    return $health
}

function Get-DiskList {
    Write-Host "  Detectando discos..." -ForegroundColor Gray
    Write-Host ""

    $disks = Get-Disk | Where-Object { $_.OperationalStatus -eq "Online" }

    if ($disks.Count -eq 0) {
        Write-Host "  [ERROR] No se detectaron discos." -ForegroundColor Red
        return $null
    }

    $i = 1
    $diskInfo = @()

    foreach ($disk in $disks) {
        $sizeGB = [math]::Round($disk.Size / 1GB, 0)

        # Tipo simple
        $tipo = if ($disk.BusType -eq "USB") { "USB" }
                elseif ($disk.BusType -eq "NVMe" -or $disk.MediaType -eq "SSD") { "SSD" }
                elseif ($disk.MediaType -eq "HDD") { "HDD" }
                else { "Disco" }

        # Obtener particiones con letra
        $particiones = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
                       Where-Object { $_.DriveLetter }

        # Detectar si tiene Windows, BitLocker, disco dinamico
        $tieneWindows = $false
        $esDiscoSistemaActual = $false
        $tieneBitLocker = $false
        $esDinamico = ($disk.PartitionStyle -eq "Dynamic")
        $volumenesInfo = @()
        $advertencias = @()

        # Advertencia disco dinamico
        if ($esDinamico) {
            $advertencias += "DISCO DINAMICO"
        }

        foreach ($part in $particiones) {
            $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
            $letra = "$($part.DriveLetter):"
            $nombre = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Sin nombre" }
            $libres = [math]::Round($vol.SizeRemaining / 1GB, 0)
            $total = [math]::Round($vol.Size / 1GB, 0)
            $bitlockerActivo = $false

            # Detectar Windows
            if (Test-Path "$letra\Windows\System32") {
                $tieneWindows = $true
                # Detectar si es el sistema ACTUAL (C:) o un Windows externo
                if ($letra -eq "$env:SystemDrive") {
                    $nombre = "WINDOWS ACTUAL - NO TOCAR"
                    $esDiscoSistemaActual = $true
                } else {
                    $nombre = "WINDOWS (externo)"
                }
            }

            # Detectar BitLocker (silencioso si no tiene permisos)
            try {
                $blStatus = Get-BitLockerVolume -MountPoint $letra -ErrorAction SilentlyContinue
                if ($blStatus -and $blStatus.ProtectionStatus -eq "On") {
                    $tieneBitLocker = $true
                    $bitlockerActivo = $true
                    $nombre = "$nombre [BITLOCKER]"
                }
            } catch { }

            $volumenesInfo += @{
                Letra = $letra
                Nombre = $nombre
                LibreGB = $libres
                TotalGB = $total
                EsWindows = (Test-Path "$letra\Windows\System32")
                BitLocker = $bitlockerActivo
            }
        }

        # Advertencias
        if ($tieneBitLocker) { $advertencias += "BITLOCKER ACTIVO" }

        # Guardar info del disco
        $diskInfo += @{
            Index = $i
            DiskNumber = $disk.Number
            HWName = $disk.FriendlyName
            SizeGB = $sizeGB
            Type = $tipo
            TieneWindows = $tieneWindows
            EsDiscoSistemaActual = $esDiscoSistemaActual
            TieneBitLocker = $tieneBitLocker
            EsDinamico = $esDinamico
            Advertencias = $advertencias
            Volumenes = $volumenesInfo
            Disk = $disk
        }
        $i++
    }

    # Mostrar tabla bonita
    Write-Host "  ╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                         DISCOS DETECTADOS                              ║" -ForegroundColor Cyan
    Write-Host "  ╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    foreach ($d in $diskInfo) {
        # Header del disco
        $icono = if ($d.Type -eq "SSD") { "[SSD]" }
                 elseif ($d.Type -eq "HDD") { "[HDD]" }
                 elseif ($d.Type -eq "USB") { "[USB]" }
                 else { "[---]" }

        $winTag = if ($d.EsDiscoSistemaActual) { " *** NO TOCAR ***" } elseif ($d.TieneWindows) { " [WINDOWS]" } else { "" }
        $blTag = if ($d.TieneBitLocker) { " [BITLOCKER]" } else { "" }
        $dynTag = if ($d.EsDinamico) { " [DINAMICO]" } else { "" }
        $hwCorto = if ($d.HWName.Length -gt 30) { $d.HWName.Substring(0,27) + "..." } else { $d.HWName }

        # ROJO = no tocar (sistema actual, bitlocker, dinamico)
        # AMARILLO = Windows externo (cuidado pero permitido)
        # BLANCO = normal
        $colorDisco = if ($d.EsDiscoSistemaActual -or $d.TieneBitLocker -or $d.EsDinamico) { "Red" } elseif ($d.TieneWindows) { "Yellow" } else { "White" }

        Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
        Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
        $headerText = "[$($d.Index)] $icono $hwCorto ($($d.SizeGB) GB)$winTag$blTag$dynTag"
        Write-Host $headerText -NoNewline -ForegroundColor $colorDisco
        $padding = 69 - $headerText.Length
        if ($padding -gt 0) { Write-Host (" " * $padding) -NoNewline }
        Write-Host " │" -ForegroundColor DarkGray
        Write-Host "  ├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray

        # Mostrar volumenes
        if ($d.Volumenes.Count -eq 0) {
            Write-Host "  │   (sin particiones visibles)                                       │" -ForegroundColor DarkGray
        } else {
            foreach ($v in $d.Volumenes) {
                $barra = ""
                $pctUsado = if ($v.TotalGB -gt 0) { [math]::Round((($v.TotalGB - $v.LibreGB) / $v.TotalGB) * 10) } else { 0 }
                $barra = ("█" * $pctUsado) + ("░" * (10 - $pctUsado))

                $colorVol = if ($v.EsWindows) { "Yellow" } else { "Green" }
                $nombreCorto = if ($v.Nombre.Length -gt 15) { $v.Nombre.Substring(0,12) + "..." } else { $v.Nombre }

                $linea = "    $($v.Letra) $nombreCorto"
                $linea = $linea.PadRight(25)
                $linea += "[$barra] $($v.LibreGB) GB libres de $($v.TotalGB) GB"

                Write-Host "  │ " -NoNewline -ForegroundColor DarkGray
                Write-Host $linea -NoNewline -ForegroundColor $colorVol
                $pad2 = 69 - $linea.Length
                if ($pad2 -gt 0) { Write-Host (" " * $pad2) -NoNewline }
                Write-Host " │" -ForegroundColor DarkGray
            }
        }
        Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
        Write-Host ""
    }

    return $diskInfo
}

function Show-HiddenDisks {
    Write-Host ""
    Write-Host "  ╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║              RESCATAR DISCO INVISIBLE / OCULTO                         ║" -ForegroundColor Yellow
    Write-Host "  ╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Buscando discos que Windows no muestra en el Explorador..." -ForegroundColor Gray
    Write-Host ""

    $allDisks = Get-Disk -ErrorAction SilentlyContinue
    $problemDisks = @()

    foreach ($disk in $allDisks) {
        $particiones = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
        $tieneLetra = ($particiones | Where-Object { $_.DriveLetter }) -ne $null
        $problemas = @()

        # Detectar problemas
        if ($disk.OperationalStatus -eq "Offline") {
            $problemas += "OFFLINE (disco desactivado)"
        }
        if ($disk.IsReadOnly) {
            $problemas += "SOLO LECTURA"
        }
        if ($disk.PartitionStyle -eq "RAW") {
            $problemas += "SIN INICIALIZAR (nuevo o borrado)"
        }
        if (-not $particiones -or $particiones.Count -eq 0) {
            $problemas += "SIN PARTICIONES"
        }
        if ($particiones -and -not $tieneLetra) {
            $problemas += "SIN LETRA ASIGNADA (C:, D:, etc.)"
        }

        # Verificar si alguna partición es RAW
        foreach ($p in $particiones) {
            $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue
            if ($vol -and $vol.FileSystem -eq "RAW") {
                $problemas += "SISTEMA DE ARCHIVOS DAÑADO (RAW)"
            }
        }

        if ($problemas.Count -gt 0) {
            $problemDisks += @{
                Disk = $disk
                DiskNumber = $disk.Number
                Name = $disk.FriendlyName
                SizeGB = [math]::Round($disk.Size / 1GB, 0)
                BusType = $disk.BusType
                Problems = $problemas
                Partitions = $particiones
                HasLetter = $tieneLetra
            }
        }
    }

    if ($problemDisks.Count -eq 0) {
        Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "  │  ¡TODOS LOS DISCOS ESTAN VISIBLES!                                  │" -ForegroundColor Green
        Write-Host "  │  No hay discos ocultos o con problemas.                             │" -ForegroundColor Green
        Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Green
        return
    }

    Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Red
    Write-Host "  │  ¡ENCONTRADOS $($problemDisks.Count) DISCO(S) CON PROBLEMAS!                                  │" -ForegroundColor Red
    Write-Host "  │  Estos discos NO aparecen en el Explorador de Windows.              │" -ForegroundColor Red
    Write-Host "  │  ¡NO LO TIRES! Se puede arreglar.                                   │" -ForegroundColor Yellow
    Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Red
    Write-Host ""

    $i = 1
    foreach ($pd in $problemDisks) {
        $tipo = if ($pd.BusType -eq "USB") { "[USB]" }
                elseif ($pd.BusType -eq "NVMe") { "[SSD]" }
                else { "[HDD]" }

        Write-Host "  ┌─────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │ " -NoNewline -ForegroundColor Yellow
        Write-Host "DISCO ${i}: $tipo $($pd.Name) ($($pd.SizeGB) GB)" -ForegroundColor White -NoNewline
        $pad = 66 - "DISCO ${i}: $tipo $($pd.Name) ($($pd.SizeGB) GB)".Length
        Write-Host (" " * [Math]::Max(0,$pad)) -NoNewline
        Write-Host " │" -ForegroundColor Yellow
        Write-Host "  ├─────────────────────────────────────────────────────────────────────┤" -ForegroundColor Yellow

        Write-Host "  │ " -NoNewline -ForegroundColor Yellow
        Write-Host "¿Por que no lo ves en Windows?" -ForegroundColor Cyan -NoNewline
        Write-Host "                                      │" -ForegroundColor Yellow

        foreach ($prob in $pd.Problems) {
            Write-Host "  │   " -NoNewline -ForegroundColor Yellow
            Write-Host "• $prob" -ForegroundColor Red -NoNewline
            $pad2 = 65 - "• $prob".Length
            Write-Host (" " * [Math]::Max(0,$pad2)) -NoNewline
            Write-Host " │" -ForegroundColor Yellow
        }

        Write-Host "  └─────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host ""
        $i++
    }

    # Ofrecer arreglar
    Write-Host "  ¿Quieres intentar ARREGLAR alguno? [1-$($problemDisks.Count) / N]: " -NoNewline -ForegroundColor Cyan
    $seleccion = Read-Host

    if ($seleccion -match "^\d+$" -and [int]$seleccion -ge 1 -and [int]$seleccion -le $problemDisks.Count) {
        $discoArreglar = $problemDisks[[int]$seleccion - 1]
        Write-Host ""
        Write-Host "  Intentando arreglar: $($discoArreglar.Name)..." -ForegroundColor Yellow
        Write-Host ""

        $arreglado = $false

        # 1. Si está offline, ponerlo online
        if ($discoArreglar.Disk.OperationalStatus -eq "Offline") {
            Write-Host "  [1] Activando disco (estaba OFFLINE)..." -ForegroundColor Gray
            try {
                Set-Disk -Number $discoArreglar.DiskNumber -IsOffline $false
                Write-Host "      OK - Disco activado" -ForegroundColor Green
                $arreglado = $true
            } catch {
                Write-Host "      ERROR: $_" -ForegroundColor Red
            }
        }

        # 2. Si es RAW (sin inicializar), preguntar si inicializar
        if ($discoArreglar.Disk.PartitionStyle -eq "RAW") {
            Write-Host ""
            Write-Host "  [!] Este disco NO ESTA INICIALIZADO." -ForegroundColor Red
            Write-Host "      Si es NUEVO o lo borraste a proposito, puedes inicializarlo." -ForegroundColor Gray
            Write-Host "      Si tenia DATOS, inicializarlo los BORRARA." -ForegroundColor Red
            Write-Host ""
            Write-Host "  ¿Inicializar disco? (BORRA TODO) [S/N]: " -NoNewline -ForegroundColor Red
            $init = Read-Host
            if ($init -match "^[Ss]") {
                Write-Host "  [2] Inicializando disco como GPT..." -ForegroundColor Gray
                try {
                    Initialize-Disk -Number $discoArreglar.DiskNumber -PartitionStyle GPT -Confirm:$false
                    Write-Host "      OK - Disco inicializado" -ForegroundColor Green

                    Write-Host "  [3] Creando particion..." -ForegroundColor Gray
                    $newPart = New-Partition -DiskNumber $discoArreglar.DiskNumber -UseMaximumSize -AssignDriveLetter
                    Write-Host "      OK - Particion creada con letra $($newPart.DriveLetter):" -ForegroundColor Green

                    Write-Host "  [4] Formateando como NTFS..." -ForegroundColor Gray
                    Format-Volume -DriveLetter $newPart.DriveLetter -FileSystem NTFS -NewFileSystemLabel "Disco USB" -Confirm:$false | Out-Null
                    Write-Host "      OK - Formateado" -ForegroundColor Green

                    $arreglado = $true
                } catch {
                    Write-Host "      ERROR: $_" -ForegroundColor Red
                }
            }
        }

        # 3. Si tiene particiones pero sin letra
        if (-not $discoArreglar.HasLetter -and $discoArreglar.Partitions) {
            Write-Host "  [2] Asignando letra de unidad..." -ForegroundColor Gray
            foreach ($part in $discoArreglar.Partitions) {
                if (-not $part.DriveLetter -and $part.Size -gt 100MB) {
                    try {
                        $usedLetters = (Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter
                        $freeLetter = [char[]](69..90) | Where-Object { $_ -notin $usedLetters } | Select-Object -First 1

                        Set-Partition -DiskNumber $discoArreglar.DiskNumber -PartitionNumber $part.PartitionNumber -NewDriveLetter $freeLetter
                        Write-Host "      OK - Asignada letra $freeLetter`:" -ForegroundColor Green
                        $arreglado = $true
                    } catch {
                        Write-Host "      ERROR: $_" -ForegroundColor Red
                    }
                }
            }
        }

        Write-Host ""
        if ($arreglado) {
            Write-Host "  ╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
            Write-Host "  ║  ¡DISCO ARREGLADO! Ahora deberia verse en el Explorador de Windows.   ║" -ForegroundColor Green
            Write-Host "  ╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        } else {
            Write-Host "  [!] No se pudo arreglar automaticamente." -ForegroundColor Yellow
            Write-Host "      Puede que necesite herramientas especializadas o el disco este dañado." -ForegroundColor Gray
        }
    }
}

function Initialize-AndFormatDisk {
    param([int]$DiskNumber)
    
    Write-Host ""
    Write-Host "  ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              INICIALIZAR Y FORMATEAR DISCO                      ║" -ForegroundColor Cyan
    Write-Host "  ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    # 1. Estilo de partición
    Write-Host "  Estilo de particion:" -ForegroundColor Yellow
    Write-Host "    [1] GPT (recomendado para discos > 2TB y UEFI)" -ForegroundColor White
    Write-Host "    [2] MBR (compatibilidad con sistemas antiguos)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Selecciona [1/2]: " -NoNewline -ForegroundColor Yellow
    $estiloOpc = Read-Host
    $estilo = if ($estiloOpc -eq "2") { "MBR" } else { "GPT" }
    
    # 2. Sistema de archivos
    Write-Host ""
    Write-Host "  Sistema de archivos:" -ForegroundColor Yellow
    Write-Host "    [1] NTFS (Windows, archivos > 4GB, recomendado)" -ForegroundColor White
    Write-Host "    [2] exFAT (compatible Windows/Mac/Linux, archivos > 4GB)" -ForegroundColor White
    Write-Host "    [3] FAT32 (maxima compatibilidad, limite 4GB por archivo)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Selecciona [1/2/3]: " -NoNewline -ForegroundColor Yellow
    $fsOpc = Read-Host
    $fileSystem = switch ($fsOpc) {
        "2" { "exFAT" }
        "3" { "FAT32" }
        default { "NTFS" }
    }
    
    # 3. Etiqueta
    Write-Host ""
    Write-Host "  Nombre/etiqueta del disco [USB]: " -NoNewline -ForegroundColor Yellow
    $label = Read-Host
    if (-not $label) { $label = "USB" }
    # Limitar a 11 caracteres para FAT32
    if ($fileSystem -eq "FAT32" -and $label.Length -gt 11) {
        $label = $label.Substring(0, 11)
    }
    
    Write-Host ""
    Write-Host "  Configuracion:" -ForegroundColor Cyan
    Write-Host "    Estilo:    $estilo" -ForegroundColor Gray
    Write-Host "    Formato:   $fileSystem" -ForegroundColor Gray
    Write-Host "    Etiqueta:  $label" -ForegroundColor Gray
    Write-Host ""
    
    try {
        # Inicializar
        Write-Host "  [1/3] Inicializando disco como $estilo..." -ForegroundColor Yellow
        Initialize-Disk -Number $DiskNumber -PartitionStyle $estilo -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green
        
        # Crear partición
        Write-Host "  [2/3] Creando particion..." -ForegroundColor Yellow
        $newPart = New-Partition -DiskNumber $DiskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
        $letra = $newPart.DriveLetter
        Write-Host "        OK - Letra asignada: $letra`:" -ForegroundColor Green
        
        # Formatear
        Write-Host "  [3/3] Formateando como $fileSystem..." -ForegroundColor Yellow
        Format-Volume -DriveLetter $letra -FileSystem $fileSystem -NewFileSystemLabel $label -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "        OK" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "  ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║  ¡DISCO LISTO PARA USAR!                                        ║" -ForegroundColor Green
        Write-Host "  ║  Unidad: $letra`:  Formato: $($fileSystem.PadRight(6)) Nombre: $($label.PadRight(15))       ║" -ForegroundColor Green
        Write-Host "  ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

        # Refrescar Explorer para que aparezca el disco
        Refresh-Explorer

    } catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        Refresh-Explorer -Silent
    }
}

function Get-PartitionList {
    param([int]$DiskNumber)

    Write-Host "  Particiones del disco $DiskNumber :" -ForegroundColor Cyan
    Write-Host ""

    $partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction SilentlyContinue |
                  Where-Object { $_.Type -ne "Reserved" -and $_.Size -gt 0 }

    if (-not $partitions -or $partitions.Count -eq 0) {
        Write-Host "  [!] No hay particiones accesibles en este disco." -ForegroundColor Yellow
        return $null
    }

    $i = 1
    $partInfo = @()

    Write-Host "  ┌────┬────────┬──────────┬──────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ ## │ LETRA  │ TAMAÑO   │ TIPO / SISTEMA ARCHIVOS              │" -ForegroundColor DarkGray
    Write-Host "  ├────┼────────┼──────────┼──────────────────────────────────────┤" -ForegroundColor DarkGray

    foreach ($part in $partitions) {
        $sizeGB = [math]::Round($part.Size / 1GB, 1)
        $letra = if ($part.DriveLetter) { "$($part.DriveLetter):" } else { "--" }

        # Obtener sistema de archivos
        $vol = Get-Volume -Partition $part -ErrorAction SilentlyContinue
        $fs = if ($vol) { $vol.FileSystem } else { $part.Type }
        if (-not $fs) { $fs = "Desconocido" }

        $line = "  │ {0,2} │ {1,-6} │ {2,6} GB │ {3,-36} │" -f $i, $letra, $sizeGB, $fs
        Write-Host $line -ForegroundColor White

        $partInfo += @{
            Index = $i
            PartitionNumber = $part.PartitionNumber
            DriveLetter = $part.DriveLetter
            SizeGB = $sizeGB
            FileSystem = $fs
            Partition = $part
        }
        $i++
    }

    Write-Host "  └────┴────────┴──────────┴──────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    return $partInfo
}

# ===============================================================================
# CREAR IMAGEN DE DISCO (VHDX/WIM)
# ===============================================================================

function New-DiskImage {
    param(
        [int]$DiskNumber,
        [string]$OutputPath,
        [string]$Format = "VHDX"
    )

    Write-Host ""
    Write-Host "  [CREAR IMAGEN DE DISCO]" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray

    $disk = Get-Disk -Number $DiskNumber
    $sizeGB = [math]::Round($disk.Size / 1GB, 1)

    # Calcular espacio usado real
    $sourcePartitions = Get-Partition -DiskNumber $DiskNumber | Where-Object { $_.DriveLetter }
    $totalUsedGB = 0
    foreach ($p in $sourcePartitions) {
        $vol = Get-Volume -Partition $p -ErrorAction SilentlyContinue
        if ($vol) { $totalUsedGB += [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 1) }
    }

    Write-Host "  Disco origen:  $($disk.FriendlyName)" -ForegroundColor White
    Write-Host "  Tamaño total:  $sizeGB GB" -ForegroundColor White
    Write-Host "  Espacio usado: $totalUsedGB GB (esto se copiara)" -ForegroundColor Yellow
    Write-Host "  Formato:       $Format" -ForegroundColor White
    Write-Host "  Destino:       $OutputPath" -ForegroundColor White
    Write-Host ""

    # Verificar espacio libre en destino
    $destDrive = (Split-Path $OutputPath -Qualifier)
    $destVol = Get-Volume -DriveLetter ($destDrive.TrimEnd(':')) -ErrorAction SilentlyContinue
    if ($destVol) {
        $freeGB = [math]::Round($destVol.SizeRemaining / 1GB, 1)
        Write-Host "  Espacio libre en destino: $freeGB GB" -ForegroundColor $(if($freeGB -gt $totalUsedGB){"Green"}else{"Red"})
        if ($freeGB -lt $totalUsedGB) {
            Write-Host "  [ERROR] No hay suficiente espacio en el destino!" -ForegroundColor Red
            return $false
        }
    }

    Write-Host ""
    Write-Host "  [ADVERTENCIA] Clonar $totalUsedGB GB puede tardar bastante tiempo." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ¿Continuar? [S/N]: " -NoNewline -ForegroundColor Yellow
    $continuar = Read-Host
    if ($continuar -notmatch "^[Ss]$") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }
    Write-Host ""
    Write-Host "  Escribe 'CLONAR' para confirmar: " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host
    if ($confirm -ne "CLONAR") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }

    # Crear directorio si no existe
    $dir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $startTime = Get-Date

    if ($Format -eq "VHDX" -or $Format -eq "VHD") {
        Write-Host ""
        Write-Host "  [1/5] Creando archivo $Format..." -ForegroundColor Cyan

        try {
            # Crear VHDX con tamaño suficiente
            $vhdSizeBytes = $disk.Size
            $vhd = New-VHD -Path $OutputPath -SizeBytes $vhdSizeBytes -Dynamic -ErrorAction Stop
            Write-Host "        Archivo creado: $OutputPath" -ForegroundColor Green

            Write-Host "  [2/5] Montando imagen..." -ForegroundColor Cyan
            Mount-VHD -Path $OutputPath -ErrorAction Stop
            Start-Sleep -Seconds 2

            $mountedVhd = Get-VHD -Path $OutputPath
            $mountedDiskNumber = $mountedVhd.DiskNumber
            Write-Host "        Montado como Disco $mountedDiskNumber" -ForegroundColor Green

            Write-Host "  [3/5] Inicializando disco virtual..." -ForegroundColor Cyan
            $srcPartStyle = $disk.PartitionStyle
            Initialize-Disk -Number $mountedDiskNumber -PartitionStyle $srcPartStyle -ErrorAction SilentlyContinue
            Write-Host "        Estilo: $srcPartStyle" -ForegroundColor Green

            Write-Host "  [4/5] Creando particiones y formateando..." -ForegroundColor Cyan

            $partIndex = 0
            foreach ($srcPart in $sourcePartitions) {
                $partIndex++
                $srcLetter = $srcPart.DriveLetter
                $srcVol = Get-Volume -Partition $srcPart -ErrorAction SilentlyContinue
                $partSizeGB = [math]::Round($srcPart.Size / 1GB, 1)
                $fs = if ($srcVol) { $srcVol.FileSystem } else { "NTFS" }
                $label = if ($srcVol) { $srcVol.FileSystemLabel } else { "Particion$partIndex" }

                Write-Host "        Creando particion $partIndex ($srcLetter`: $partSizeGB GB $fs)..." -ForegroundColor Gray

                # Crear particion en VHD
                $newPart = New-Partition -DiskNumber $mountedDiskNumber -Size $srcPart.Size -ErrorAction SilentlyContinue

                if ($newPart) {
                    # Buscar letra libre
                    $usedLetters = (Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter
                    $freeLetter = [char[]](71..90) | Where-Object { $_ -notin $usedLetters } | Select-Object -First 1

                    Set-Partition -DiskNumber $mountedDiskNumber -PartitionNumber $newPart.PartitionNumber -NewDriveLetter $freeLetter -ErrorAction SilentlyContinue
                    Format-Volume -DriveLetter $freeLetter -FileSystem $fs -NewFileSystemLabel $label -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

                    Write-Host "        Particion creada con letra $freeLetter`:" -ForegroundColor Green
                }
            }

            Write-Host "  [5/5] Copiando datos con ROBOCOPY..." -ForegroundColor Cyan
            Write-Host ""

            # Obtener mapeo de letras origen -> destino
            $dstPartitions = Get-Partition -DiskNumber $mountedDiskNumber | Where-Object { $_.DriveLetter } | Sort-Object PartitionNumber

            for ($i = 0; $i -lt [Math]::Min($sourcePartitions.Count, $dstPartitions.Count); $i++) {
                $srcLetter = $sourcePartitions[$i].DriveLetter
                $dstLetter = $dstPartitions[$i].DriveLetter
                $srcVol = Get-Volume -DriveLetter $srcLetter -ErrorAction SilentlyContinue
                $usedGB = if ($srcVol) { [math]::Round(($srcVol.Size - $srcVol.SizeRemaining) / 1GB, 1) } else { "?" }

                Write-Host "  ────────────────────────────────────────────────────" -ForegroundColor DarkGray
                Write-Host "  Copiando $srcLetter`:\ -> $dstLetter`:\ ($usedGB GB)" -ForegroundColor Yellow
                Write-Host "  ────────────────────────────────────────────────────" -ForegroundColor DarkGray

                # Robocopy con todas las opciones para copia completa
                # /MIR = Mirror (copia todo)
                # /COPYALL = Copia atributos, seguridad, owner, auditing
                # /DCOPY:DAT = Copia atributos de directorios
                # /R:1 /W:1 = Solo 1 reintento, 1 segundo de espera
                # /MT:8 = 8 threads paralelos
                # /XJ = Excluir junction points (evita loops)
                # /XD = Excluir directorios problematicos

                $robocopyArgs = @(
                    "$srcLetter`:\"
                    "$dstLetter`:\"
                    "/MIR"
                    "/COPY:DAT"
                    "/DCOPY:DAT"
                    "/R:1"
                    "/W:1"
                    "/MT:32"
                    "/J"
                    "/XJ"
                    "/XD", "`"System Volume Information`"", "`"`$Recycle.Bin`"", "`"Recovery`""
                    "/XF", "pagefile.sys", "hiberfil.sys", "swapfile.sys"
                    "/NP"
                    "/LOG+:$script:CurrentLogFile"
                    "/TEE"
                )

                $robocopyCmd = "robocopy.exe " + ($robocopyArgs -join " ")
                Write-Host "  Ejecutando: robocopy $srcLetter`:\ $dstLetter`:\ /MIR ..." -ForegroundColor Gray

                $robocopyProcess = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -Wait -PassThru

                # Robocopy exit codes: 0-7 = OK, 8+ = Error
                if ($robocopyProcess.ExitCode -lt 8) {
                    Write-Host "  [OK] $srcLetter`:\ copiado correctamente" -ForegroundColor Green
                } else {
                    Write-Host "  [!] Algunos archivos no se pudieron copiar (codigo: $($robocopyProcess.ExitCode))" -ForegroundColor Red
                }
                Write-Host ""
            }

            # Desmontar
            Write-Host "  Desmontando imagen..." -ForegroundColor Gray
            Dismount-VHD -Path $OutputPath

            $duration = (Get-Date) - $startTime
            $durationStr = "{0:hh\:mm\:ss}" -f $duration

            Write-Host ""
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host "  [OK] IMAGEN CREADA EXITOSAMENTE!" -ForegroundColor Green
            Write-Host "  ============================================================" -ForegroundColor Green
            Write-Host "  Archivo:  $OutputPath" -ForegroundColor White
            Write-Host "  Duracion: $durationStr" -ForegroundColor White
            Write-Host "  Tamaño:   $([math]::Round((Get-Item $OutputPath).Length / 1GB, 2)) GB" -ForegroundColor White
            Write-Host ""

        } catch {
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            # Intentar desmontar si hay error
            Dismount-VHD -Path $OutputPath -ErrorAction SilentlyContinue
            return $false
        }

    } elseif ($Format -eq "WIM") {
        # Usar DISM para crear WIM (mas rapido y comprimido)
        Write-Host ""
        Write-Host "  Creando imagen WIM con DISM..." -ForegroundColor Cyan
        Write-Host "  (WIM es mas eficiente para backups de Windows)" -ForegroundColor Gray
        Write-Host ""

        foreach ($part in $sourcePartitions) {
            $letra = $part.DriveLetter
            $wimPath = $OutputPath -replace "\.wim$", "_$letra.wim"
            $srcVol = Get-Volume -DriveLetter $letra -ErrorAction SilentlyContinue
            $usedGB = if ($srcVol) { [math]::Round(($srcVol.Size - $srcVol.SizeRemaining) / 1GB, 1) } else { "?" }

            Write-Host "  Capturando $letra`:\ ($usedGB GB) -> $wimPath" -ForegroundColor Yellow

            $dismArgs = "/Capture-Image /ImageFile:`"$wimPath`" /CaptureDir:$letra`:\ /Name:`"Backup_$letra`" /Description:`"ARCAMIA-MEMMEM Backup`" /Compress:fast /CheckIntegrity"

            try {
                $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -NoNewWindow -Wait -PassThru
                if ($process.ExitCode -eq 0) {
                    $wimSize = [math]::Round((Get-Item $wimPath).Length / 1GB, 2)
                    Write-Host "  [OK] $letra capturada ($wimSize GB comprimido)" -ForegroundColor Green
                } else {
                    Write-Host "  [!] Error capturando $letra (codigo: $($process.ExitCode))" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            }
        }

        $duration = (Get-Date) - $startTime
        $durationStr = "{0:hh\:mm\:ss}" -f $duration
        Write-Host ""
        Write-Host "  [OK] Captura WIM completada en $durationStr" -ForegroundColor Green
    }

    return $true
}

# ===============================================================================
# NOTA: Las funciones Copy-DiskRaw y Copy-DiskFFU fueron eliminadas en v2.0
# - Copy-DiskRaw: Windows bloquea acceso raw a discos montados
# - Copy-DiskFFU: Solo funciona en discos GPT, falla en MBR
# Ahora usamos WIMLIB que es mas rapido y funciona en todos los casos
# ===============================================================================

# (Codigo deprecado eliminado - ver historial git para versiones anteriores)
# ===============================================================================
# CLONAR DISCO RAPIDO CON WIMLIB (MAS RAPIDO QUE DISM)
# ===============================================================================

function Copy-DiskFast {
    param(
        [int]$SourceDisk,
        [int]$DestDisk
    )

    $wimlib = $script:CONFIG.WimlibPath

    # =========================================================================
    # CABECERA
    # =========================================================================
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║           CLONADO RAPIDO v2.3 (WIMLIB + VSS + EFI)                ║" -ForegroundColor Green
    Write-Host "  ║           Velocidad: 100-200+ MB/s | Bootable                     ║" -ForegroundColor White
    Write-Host "  ║                                                                   ║" -ForegroundColor Green
    Write-Host "  ║           [ESC] o [Q] para cancelar en cualquier momento          ║" -ForegroundColor DarkGray
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    # VERIFICACION INICIAL
    if (-not (Test-DiskConnected -DiskNumber $SourceDisk -Nombre "Disco origen")) { return $false }
    if (-not (Test-DiskConnected -DiskNumber $DestDisk -Nombre "Disco destino")) { return $false }

    $src = Get-Disk -Number $SourceDisk
    $dst = Get-Disk -Number $DestDisk

    $srcName = if ($src.FriendlyName.Length -gt 45) { $src.FriendlyName.Substring(0,42) + "..." } else { $src.FriendlyName }
    $dstName = if ($dst.FriendlyName.Length -gt 45) { $dst.FriendlyName.Substring(0,42) + "..." } else { $dst.FriendlyName }
    $srcInfo = "$([math]::Round($src.Size/1GB, 1)) GB - $($src.PartitionStyle)"
    $dstInfo = "$([math]::Round($dst.Size/1GB, 1)) GB - $($dst.PartitionStyle)"

    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ ORIGEN:  [$SourceDisk] $($srcName.PadRight(45)) │" -ForegroundColor White
    Write-Host "  │          $($srcInfo.PadRight(56)) │" -ForegroundColor Gray
    Write-Host "  │ DESTINO: [$DestDisk] $($dstName.PadRight(45)) │" -ForegroundColor White
    Write-Host "  │          $($dstInfo.PadRight(56)) │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    # =========================================================================
    # DETECTAR TODAS LAS PARTICIONES (incluyendo EFI, MSR, Recovery)
    # =========================================================================
    $allSrcPartitions = Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue |
                        Where-Object { $_.Size -gt 1MB } |
                        Sort-Object PartitionNumber

    # Clasificar particiones
    $efiPartition = $allSrcPartitions | Where-Object { $_.Type -eq "System" -or $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" } | Select-Object -First 1
    $msrPartition = $allSrcPartitions | Where-Object { $_.Type -eq "Reserved" -or $_.GptType -eq "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" } | Select-Object -First 1
    $recoveryPartition = $allSrcPartitions | Where-Object { $_.Type -eq "Recovery" -or $_.GptType -eq "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}" } | Select-Object -First 1

    # Particiones de datos (con letra o que contengan Windows)
    $dataPartitions = $allSrcPartitions | Where-Object {
        $_.Type -eq "Basic" -and $_.Size -gt 100MB
    }

    # Detectar si el disco es bootable (tiene Windows)
    $isBootable = $false
    $windowsPartition = $null
    foreach ($p in $dataPartitions) {
        $letter = $p.DriveLetter
        if (-not $letter) {
            # Asignar letra temporal para verificar
            $tempLetters = @('R','S','T','U','V','W') | Where-Object { -not (Test-Path "${_}:\") }
            if ($tempLetters.Count -gt 0) {
                try {
                    Add-PartitionAccessPath -DiskNumber $SourceDisk -PartitionNumber $p.PartitionNumber -AccessPath "$($tempLetters[0]):\" -ErrorAction SilentlyContinue
                    $letter = $tempLetters[0]
                    Start-Sleep -Milliseconds 250
                } catch {}
            }
        }
        if ($letter -and (Test-Path "$letter`:\Windows\System32\config")) {
            $isBootable = $true
            $windowsPartition = $p
            break
        }
    }

    Write-Host "  ANALISIS DEL DISCO ORIGEN:" -ForegroundColor Yellow
    Write-Host "    Estilo: $($src.PartitionStyle)" -ForegroundColor Gray
    if ($efiPartition) { Write-Host "    [EFI] Particion de sistema: $([math]::Round($efiPartition.Size/1MB)) MB" -ForegroundColor Cyan }
    if ($msrPartition) { Write-Host "    [MSR] Reservada Microsoft: $([math]::Round($msrPartition.Size/1MB)) MB" -ForegroundColor DarkGray }
    if ($recoveryPartition) { Write-Host "    [REC] Particion de recuperacion: $([math]::Round($recoveryPartition.Size/1MB)) MB" -ForegroundColor DarkGray }
    Write-Host "    [DAT] Particiones de datos: $($dataPartitions.Count)" -ForegroundColor White
    if ($isBootable) {
        Write-Host "    [WIN] Disco BOOTABLE detectado" -ForegroundColor Green
    } else {
        Write-Host "    [---] Disco de DATOS (no bootable)" -ForegroundColor Yellow
    }
    Write-Host ""

    # Obtener particiones con letra para capturar (metodo original como fallback)
    $srcPartitions = Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue |
                     Where-Object { $_.DriveLetter -and $_.Size -gt 100MB }

    if (-not $srcPartitions -or $srcPartitions.Count -eq 0) {
        Write-Host "  [ERROR] No se encontraron particiones con datos en el disco origen" -ForegroundColor Red
        return $false
    }

    # Calcular espacio usado total
    $totalUsedBytes = 0
    $partitionInfo = @()
    foreach ($p in $srcPartitions) {
        $usedSpace = 0
        try {
            $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
            if ($vol) {
                $usedSpace = $vol.Size - $vol.SizeRemaining
                $totalUsedBytes += $usedSpace
            }
        } catch {}
        $partitionInfo += @{ Letter = $p.DriveLetter; Size = $p.Size; Used = $usedSpace }
    }

    Write-Host "  PARTICIONES A CLONAR:" -ForegroundColor Yellow
    foreach ($pi in $partitionInfo) {
        $usedGB = [math]::Round($pi.Used / 1GB, 1)
        $sizeGB = [math]::Round($pi.Size / 1GB, 1)
        Write-Host "    [$($pi.Letter):] $usedGB GB usado de $sizeGB GB" -ForegroundColor Gray
    }
    Write-Host ""
    $totalUsedGB = [math]::Round($totalUsedBytes / 1GB, 1)
    Write-Host "  TOTAL A CLONAR: " -NoNewline -ForegroundColor White
    Write-Host "$totalUsedGB GB" -ForegroundColor Cyan
    Write-Host ""

    # Verificar espacio en destino
    if ($dst.Size -lt $totalUsedBytes) {
        Write-Host "  [ERROR] Disco destino muy pequeno ($([math]::Round($dst.Size/1GB, 1)) GB < $totalUsedGB GB)" -ForegroundColor Red
        return $false
    }

    # DOBLE CONFIRMACION
    $actionDesc = "CLONAR disco $SourceDisk ($srcName) a disco $DestDisk ($dstName)"
    $targetDesc = "Disco $DestDisk - $dstName ($([math]::Round($dst.Size/1GB, 1)) GB)"

    if (-not (Confirm-CriticalAction -Action $actionDesc -Keyword "CLONAR" -TargetName $targetDesc -DangerLevel "danger")) {
        return $false
    }

    # Crear log
    Start-CloneLog -Operation "Clonado Rapido WIMLIB" -Source "Disco $SourceDisk" -Destination "Disco $DestDisk"

    $startTime = Get-Date
    $wimFolder = Join-Path $env:TEMP "CLONADISCOS_WIM"
    if (Test-Path $wimFolder) { Remove-Item $wimFolder -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -Path $wimFolder -ItemType Directory -Force | Out-Null

    # Suprimir popups de formateo
    Disable-FormatPopups

    Clear-Host
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                    CLONANDO DISCO...                              ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    # =========================================================================
    # FASE 1/4: CAPTURAR CON WIMLIB
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 1/4: CAPTURANDO PARTICIONES" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Update-Monitor -Etapa "FASE 1/4: Capturando particiones" -Progreso 0 -ProgresoGlobal 0 -Log "Iniciando captura"

    $wimFiles = @()
    $partIndex = 0
    $totalPartitions = $srcPartitions.Count
    $capturedBytes = 0

    # Informar modo de captura
    if ($src.BusType -eq "USB") {
        Write-Host "  Modo: Captura directa (disco USB, sin VSS)" -ForegroundColor Cyan
    } else {
        Write-Host "  Modo: VSS snapshot (disco interno)" -ForegroundColor Cyan
    }
    Write-Host ""

    # FRASES RANDOM FASE 1 - escaneo (neutras, spanglish loco)
    $frasesFase1 = @(
        "Eeeh tranqui", "Calma calabaza", "Easy easy", "Sin prisas",
        "Relaja el body", "Zen mode ON", "Ohmmmmm", "Respira hondo",
        "Cuenta hasta 10", "Namaste", "Inner peace", "Tranquilidad",
        "Suave suavecito", "Chill chill", "Take it easy", "No stress",
        "Pon cafe YA", "CAFE AHORA", "Sin cafe no clon", "Necesito cafeina",
        "Cortado doble", "Espresso time", "Cafecito pls", "Java time",
        "Cafe con leche", "Descafeinao no", "Coffee loading", "Brewing...",
        "Un cafe anda", "Cafe o nada", "Cafeina low", "Need caffeine",
        "NO TOQUES", "Manos quietas", "Shhhhhh", "Silencio se clona",
        "Do not disturb", "No me cierres", "Cierra y lloro", "Dejame currar",
        "Ni se te ocurra", "Working here", "AFK moment", "Busy busy",
        "Hands off", "Dont touch", "Im working", "Not now pls",
        "Modo tortuga", "Caracol mode", "Slow mo", "56k modem vibes",
        "Explorer vibes", "Como Hacienda", "Windows Update", "Dial up era",
        "Fax machine", "Telegrafo mode", "Paloma mensajera", "Burocracia",
        "Lenteja mode", "Slow is life", "No hay prisa", "Despacito",
        "Escaneanding", "Buscanding", "Checkanding", "Pensanding",
        "Calculanding", "Meditanding", "Filosofanding", "Observanding",
        "Analizanding", "Procesanding", "Indexanding", "Contanding",
        "Readingando", "Listingando", "Workingando", "Loadingando",
        "Zzzzzzz", "Bostezo total", "Que largo esto", "Aburrimiento max",
        "Muchos bytes eh", "Infinito wait", "So bored", "Send help pls",
        "Menudo toston", "Que pesadez", "So boring", "Eternal wait",
        "Tu puedes", "Dale dale", "Vamos vamos", "Sigue asi",
        "Si se puede", "You got this", "Believe", "Animo",
        "Go go go", "Keep going", "Almost there", "Ya falta poco",
        "Venga venga", "Come on", "Lets go", "Vamos alla",
        "Still alive", "Trust process", "Paciencia", "Esperanding",
        "Cruza dedos", "Toco madera", "Ojala funcione", "Uy uy uy",
        "A ver que pasa", "Rezanding", "Tranquilanding", "Ahi vamos"
    )
    # FRASES RANDOM FASE 2+ - copia activa (spanglish)
    $frases = @(
        "Clonanding", "Copianding", "Movending", "Traballanding",
        "Procesanding", "Analizanding", "Calculanding", "Esperanding",
        "Optimizanding", "Preparanding", "Sincronizanding", "Leyending",
        "Transfering", "Bytesanding", "Datosanding", "Volanding"
    )
    $coloresCMYK = @("Cyan", "Magenta", "Yellow", "Gray")
    $colorIdx = 0
    $fraseActual = $frasesFase1 | Get-Random
    $ultimoCambio = Get-Date
    $spinChars = @('+', '*', '-', '·')
    $spinIdx = 0

    foreach ($p in $srcPartitions) {
        $partIndex++
        $letter = $p.DriveLetter
        $wimPath = Join-Path $wimFolder "part_${letter}.wim"

        # Calcular espacio usado
        $srcUsedBytes = 0
        try {
            $vol = Get-Volume -DriveLetter $letter -ErrorAction SilentlyContinue
            if ($vol) { $srcUsedBytes = $vol.Size - $vol.SizeRemaining }
        } catch {}
        $srcUsedGB = [math]::Round($srcUsedBytes / 1GB, 1)

        Write-Host ""
        Write-Host "  Particion $partIndex/$totalPartitions`: ${letter}:\ ($srcUsedGB GB)" -ForegroundColor White
        Write-Host "  Iniciando captura..." -NoNewline -ForegroundColor Gray
        [Console]::Out.Flush()
        Write-CloneLog "Capturando $letter con wimlib ($srcUsedGB GB)"

        $captureStart = Get-Date

        # Discos USB no necesitan VSS (no hay archivos abiertos)
        $useVSS = ($src.BusType -ne "USB")

        # Ruta origen SIN barra final (wimlib funciona mejor asi)
        $srcPath = "${letter}:"

        Write-CloneLog "Origen: $srcPath | Destino WIM: $wimPath"

        try {
            # Verificar que wimlib existe
            if (-not (Test-Path $wimlib)) {
                throw "wimlib no encontrado en: $wimlib"
            }

            # Limpiar archivos de salida anteriores (silenciar si bloqueados)
            Remove-Item "$wimFolder\wimlib_out.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item "$wimFolder\wimlib_err.txt" -Force -ErrorAction SilentlyContinue

            # Construir argumentos para wimlib
            $wimlibArgs = @("capture", $srcPath, $wimPath, "Particion_$letter", "--compress=none", "--no-acls")
            if ($useVSS) { $wimlibArgs += "--snapshot" }
            Write-CloneLog "WIMLIB: $wimlib $($wimlibArgs -join ' ')"
            Write-CloneLog "WIM destino: $wimPath"

            # Ejecutar wimlib EN LA MISMA CONSOLA (progreso en tiempo real)
            Write-Host ""
            Write-CloneLog "Ejecutando wimlib en consola..."

            # Ejecutar wimlib con Start-Process -NoNewWindow -Wait (SIN redireccion)
            $wimlibArgsArray = @("capture", $srcPath, $wimPath, "Particion_$letter", "--compress=none", "--no-acls")
            if ($useVSS) { $wimlibArgsArray += "--snapshot" }
            Write-CloneLog "WIMLIB: $wimlib $($wimlibArgsArray -join ' ')"

            # Start-Process SIN redireccion muestra output en consola
            $proc = Start-Process -FilePath $wimlib -ArgumentList $wimlibArgsArray -NoNewWindow -Wait -PassThru
            $exitCode = $proc.ExitCode

            Write-Host ""

            # Detectar error VSS por exit code
            $isVssError = ($exitCode -eq 89)
            if (-not $isVssError -and (Test-Path "$wimFolder\wimlib_err.txt")) {
                $errText = Get-Content "$wimFolder\wimlib_err.txt" -Raw -ErrorAction SilentlyContinue
                if ($errText -match "VSS|snapshot|80042308") { $isVssError = $true }
            }

            # =====================================================================
            # FALLBACK: Si VSS falla (codigo 89), reintentar sin --snapshot
            # =====================================================================
            $captureSuccess = $false
            $usedVSS = $true

            if ($isVssError) {
                Write-Host "  [!] VSS no disponible, reintentando sin snapshot..." -ForegroundColor Yellow
                Write-CloneLog "VSS fallo (codigo 89), reintentando sin snapshot"

                # Eliminar WIM parcial si existe
                if (Test-Path $wimPath) { Remove-Item $wimPath -Force -ErrorAction SilentlyContinue }

                # Argumentos sin --snapshot
                $wimlibArgsNoVSS = @(
                    "capture"
                    "${letter}:\"
                    $wimPath
                    "Particion_$letter"
                    "--compress=none"
                    "--no-acls"
                )

                $captureStart = Get-Date  # Reiniciar contador

                # EJECUTAR WIMLIB DIRECTAMENTE (sin redireccion - la redireccion rompe wimlib)
                Write-Host ""
                Write-CloneLog "VSS Retry: $wimlib $($wimlibArgsNoVSS -join ' ')"

                $procRetry = Start-Process -FilePath $wimlib -ArgumentList $wimlibArgsNoVSS -NoNewWindow -Wait -PassThru
                $retryExitCode = $procRetry.ExitCode

                Write-Host ""

                if ($retryExitCode -eq 0 -and (Test-Path $wimPath)) {
                    $usedVSS = $false
                    $captureSuccess = $true
                } else {
                    throw "wimlib fallo sin VSS (codigo $retryExitCode)"
                }
            } elseif ($exitCode -eq 0 -and (Test-Path $wimPath)) {
                $captureSuccess = $true
            } else {
                # Esperar un momento para que se escriban los logs
                Start-Sleep -Milliseconds 250
                $errContent = ""
                $outContent = ""
                if (Test-Path "$wimFolder\wimlib_err.txt") {
                    $errContent = Get-Content "$wimFolder\wimlib_err.txt" -Raw -ErrorAction SilentlyContinue
                }
                if (Test-Path "$wimFolder\wimlib_out.txt") {
                    $outContent = Get-Content "$wimFolder\wimlib_out.txt" -Raw -ErrorAction SilentlyContinue
                }
                # Mostrar informacion de debug
                $debugInfo = "ARGS: $($wimlibArgs -join ' ')"
                if ($errContent) { $debugInfo += "`nSTDERR: $errContent" }
                if ($outContent -and -not $errContent) { $debugInfo += "`nSTDOUT: $outContent" }
                if (-not $errContent -and -not $outContent) { $debugInfo += "`n(Sin output - verificar ruta wimlib: $wimlib)" }
                throw "wimlib fallo (codigo $exitCode):`n$debugInfo"
            }

            if ($captureSuccess) {
                $finalSize = (Get-Item $wimPath).Length
                $totalTime = (Get-Date) - $captureStart
                $finalSpeed = [math]::Round(($finalSize / 1MB) / $totalTime.TotalSeconds, 1)
                $capturedBytes += $finalSize

                $vssNote = if ($usedVSS) { "" } else { " (sin VSS)" }
                Write-Host "  [OK] $([math]::Round($finalSize/1GB, 2)) GB capturado$vssNote en $([math]::Round($totalTime.TotalSeconds)) seg ($finalSpeed MB/s)" -ForegroundColor Green
                $wimFiles += @{ Letter = $letter; Path = $wimPath; OriginalSize = $p.Size; WimSize = $finalSize }
                Write-CloneLog "Captura OK$vssNote`: $([math]::Round($finalSize/1GB, 2)) GB - $finalSpeed MB/s"
            }
        } catch {
            Write-Host "  [ERROR] $_" -ForegroundColor Red
            Write-CloneLog "ERROR capturando $letter : $_"
        }
    }

    if ($wimFiles.Count -eq 0) {
        Write-Host ""
        Write-Host "  [ERROR] No se pudo capturar ninguna particion" -ForegroundColor Red
        Enable-FormatPopups
        Stop-CloneLog -Success $false
        return $false
    }

    # =========================================================================
    # FASE 2/4: PREPARAR DISCO DESTINO (con soporte EFI/GPT)
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 2/4: PREPARANDO DISCO DESTINO" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Update-Monitor -Etapa "FASE 2/4: Preparando disco destino" -ProgresoGlobal 25 -Log "Preparando disco"
    Write-Host ""

    # Variable para guardar letra de EFI del destino (para bootloader)
    $script:DstEfiLetter = $null

    try {
        Write-Host "  [1/4] Limpiando disco $DestDisk..." -ForegroundColor Gray
        Clear-Disk -Number $DestDisk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green

        $partStyle = $src.PartitionStyle
        Write-Host "  [2/4] Inicializando como $partStyle..." -ForegroundColor Gray
        Initialize-Disk -Number $DestDisk -PartitionStyle $partStyle -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green

        Write-Host "  [3/4] Creando estructura de particiones..." -ForegroundColor Gray
        $dstLetters = @()
        $availableLetters = @('R','S','T','U','V','W','X','Y','Z') | Where-Object { -not (Test-Path "${_}:\") }

        # =====================================================================
        # CREAR PARTICIONES DE SISTEMA SI ES GPT BOOTABLE
        # =====================================================================
        if ($partStyle -eq "GPT" -and $isBootable -and $efiPartition) {
            Write-Host "        Creando particion EFI (FAT32)..." -ForegroundColor Cyan

            # Crear EFI System Partition (100-500 MB)
            $efiSize = [math]::Max(100MB, $efiPartition.Size)
            $efiSize = [math]::Min(500MB, $efiSize)  # No mas de 500MB

            # Usar diskpart para crear particion EFI (PowerShell no puede crear EFI directamente)
            $efiLetter = $availableLetters[0]
            $availableLetters = $availableLetters[1..($availableLetters.Count-1)]

            $dpScript = @"
select disk $DestDisk
create partition efi size=$([math]::Floor($efiSize/1MB))
format quick fs=fat32 label="System"
assign letter=$efiLetter
"@
            $dpFile = "$env:TEMP\dp_efi.txt"
            $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
            $dpResult = & diskpart /s $dpFile 2>&1
            Remove-Item $dpFile -Force -ErrorAction SilentlyContinue

            if (Test-Path "${efiLetter}:\") {
                Write-Host "        ${efiLetter}:\ EFI creada (FAT32)" -ForegroundColor Green
                $script:DstEfiLetter = $efiLetter
                Write-CloneLog "Particion EFI creada: ${efiLetter}:\"
            } else {
                Write-Host "        [!] Error creando EFI, continuando..." -ForegroundColor Yellow
            }

            # Crear MSR (Microsoft Reserved Partition) - 16MB, sin letra
            Write-Host "        Creando particion MSR (16 MB)..." -ForegroundColor DarkGray
            $dpScript = @"
select disk $DestDisk
create partition msr size=16
"@
            $dpFile = "$env:TEMP\dp_msr.txt"
            $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
            & diskpart /s $dpFile 2>&1 | Out-Null
            Remove-Item $dpFile -Force -ErrorAction SilentlyContinue
            Write-Host "        MSR creada" -ForegroundColor DarkGray
        }

        # =====================================================================
        # CREAR PARTICIONES DE DATOS
        # =====================================================================
        Write-Host "  [4/4] Creando particiones de datos..." -ForegroundColor Gray

        foreach ($wim in $wimFiles) {
            $newLetter = $availableLetters[0]
            $availableLetters = $availableLetters[1..($availableLetters.Count-1)]

            if ($wim -eq $wimFiles[-1]) {
                # Ultima particion: usar todo el espacio restante
                $newPart = New-Partition -DiskNumber $DestDisk -UseMaximumSize -DriveLetter $newLetter
            } else {
                $newPart = New-Partition -DiskNumber $DestDisk -Size $wim.OriginalSize -DriveLetter $newLetter
            }

            Format-Volume -DriveLetter $newLetter -FileSystem NTFS -NewFileSystemLabel "Clone_$($wim.Letter)" -Force -Confirm:$false | Out-Null
            Write-Host "        ${newLetter}:\ creada y formateada (NTFS)" -ForegroundColor Gray

            $dstLetters += @{ OrigLetter = $wim.Letter; NewLetter = $newLetter; WimPath = $wim.Path; WimSize = $wim.WimSize; IsWindows = ($windowsPartition -and $wim.Letter -eq $windowsPartition.DriveLetter) }
        }

        Write-Host "  [OK] Estructura de particiones creada" -ForegroundColor Green
        if ($script:DstEfiLetter) {
            Write-Host "        EFI: ${script:DstEfiLetter}:\" -ForegroundColor Cyan
        }
        Write-Host "        Datos: $($dstLetters.Count) particion(es)" -ForegroundColor White

    } catch {
        Write-Host "  [ERROR] Preparando disco: $_" -ForegroundColor Red
        Enable-FormatPopups
        Stop-CloneLog -Success $false
        return $false
    }

    # =========================================================================
    # FASE 3/4: APLICAR WIMS
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 3/4: RESTAURANDO DATOS" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Update-Monitor -Etapa "FASE 3/4: Restaurando datos" -ProgresoGlobal 50 -Log "Iniciando restauracion"

    $applyIndex = 0
    foreach ($dstPart in $dstLetters) {
        $applyIndex++

        $wimSizeBytes = $dstPart.WimSize
        $expectedGB = [math]::Round($wimSizeBytes / 1GB, 1)

        Write-Host ""
        Write-Host "  Particion $applyIndex/$($dstLetters.Count): $($dstPart.OrigLetter): -> $($dstPart.NewLetter):\ ($expectedGB GB)" -ForegroundColor White
        Write-Host "  Iniciando restauracion..." -NoNewline -ForegroundColor Gray
        [Console]::Out.Flush()
        Write-CloneLog "Aplicando a $($dstPart.NewLetter):\"

        $applyStart = Get-Date

        $destPath = "$($dstPart.NewLetter)`:\"
        $wimlibArgs = @(
            "apply"
            $dstPart.WimPath
            "1"
            $destPath
            "--no-acls"
        )

        try {
            # EJECUTAR WIMLIB DIRECTAMENTE (sin redireccion - mismo fix que capture)
            # La redireccion de stdout rompe wimlib, ejecutar directo muestra progreso real
            Write-Host ""
            Write-CloneLog "Ejecutando: $wimlib $($wimlibArgs -join ' ')"

            $procApply = Start-Process -FilePath $wimlib -ArgumentList $wimlibArgs -NoNewWindow -Wait -PassThru
            $exitCode = $procApply.ExitCode

            Write-Host ""
            $totalTime = (Get-Date) - $applyStart

            if ($exitCode -eq 0) {
                $finalSpeed = [math]::Round(($wimSizeBytes / 1MB) / $totalTime.TotalSeconds, 1)
                Write-Host "  [OK] Restaurado en $([math]::Round($totalTime.TotalSeconds)) seg ($finalSpeed MB/s)" -ForegroundColor Green
                Write-CloneLog "Aplicado OK - $finalSpeed MB/s"
            } else {
                throw "wimlib apply fallo (codigo $exitCode)"
            }
        } catch {
            Write-Host "  [ERROR] $_" -ForegroundColor Red
            Write-CloneLog "ERROR aplicando: $_"
        }
    }

    # =========================================================================
    # FASE 4/4: REPARAR BOOTLOADER (con soporte EFI correcto)
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 4/4: FINALIZANDO" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Update-Monitor -Etapa "FASE 4/4: Finalizando" -ProgresoGlobal 90 -Log "Configurando bootloader"
    Write-Host ""

    $bootRepaired = $false

    if ($isBootable) {
        Write-Host "  [1/3] Configurando bootloader..." -ForegroundColor Gray

        # Encontrar la particion de Windows en el destino
        $winDstLetter = $null
        foreach ($d in $dstLetters) {
            if ($d.IsWindows -or (Test-Path "$($d.NewLetter):\Windows\System32\config")) {
                $winDstLetter = $d.NewLetter
                break
            }
        }

        if ($winDstLetter) {
            Write-Host "        Windows detectado en ${winDstLetter}:\" -ForegroundColor Gray

            if ($partStyle -eq "GPT" -and $script:DstEfiLetter) {
                # ============================================================
                # COPIAR EFI ORIGEN → EFI DESTINO (archivos OEM, drivers, etc.)
                # ============================================================
                if ($efiPartition) {
                    Write-Host "        Copiando archivos EFI del origen..." -ForegroundColor Gray
                    $srcEfiLetter = $null

                    # Asignar letra temporal a la EFI del origen
                    $tempEfiLetters = @('J','K','N','O','P') | Where-Object { -not (Test-Path "${_}:\") }
                    if ($tempEfiLetters.Count -gt 0) {
                        try {
                            Add-PartitionAccessPath -DiskNumber $SourceDisk -PartitionNumber $efiPartition.PartitionNumber -AccessPath "$($tempEfiLetters[0]):\" -ErrorAction SilentlyContinue
                            $srcEfiLetter = $tempEfiLetters[0]
                            Start-Sleep -Milliseconds 250

                            if (Test-Path "${srcEfiLetter}:\EFI") {
                                # Copiar contenido de la EFI (excepto Boot de Windows que sera recreado)
                                $robocopyArgs = @(
                                    "${srcEfiLetter}:\EFI"
                                    "$($script:DstEfiLetter):\EFI"
                                    "/E"
                                    "/NFL", "/NDL", "/NJH", "/NJS"
                                    "/XD", "Microsoft"  # Excluir Microsoft (sera creado por bcdboot)
                                )
                                & robocopy @robocopyArgs 2>&1 | Out-Null
                                Write-Host "        Archivos EFI copiados" -ForegroundColor Gray
                                Write-CloneLog "Archivos EFI copiados de ${srcEfiLetter}: a $($script:DstEfiLetter):"
                            }

                            # Quitar letra temporal de EFI origen
                            Remove-PartitionAccessPath -DiskNumber $SourceDisk -PartitionNumber $efiPartition.PartitionNumber -AccessPath "${srcEfiLetter}:\" -ErrorAction SilentlyContinue
                        } catch {
                            Write-Host "        [!] No se pudo copiar EFI origen: $_" -ForegroundColor Yellow
                        }
                    }
                }

                # ============================================================
                # BCDBOOT PARA GPT/UEFI - Apuntar a la EFI correctamente
                # ============================================================
                Write-Host "        Modo: GPT/UEFI (EFI en $($script:DstEfiLetter):\)" -ForegroundColor Cyan
                Write-CloneLog "Ejecutando bcdboot UEFI: Windows=$winDstLetter EFI=$($script:DstEfiLetter)"

                $bcdbootCmd = "bcdboot ${winDstLetter}:\Windows /s $($script:DstEfiLetter): /f UEFI /l es-ES"
                Write-Host "        Comando: $bcdbootCmd" -ForegroundColor DarkGray

                try {
                    $bcdResult = & cmd /c $bcdbootCmd 2>&1
                    $bcdOutput = $bcdResult -join " "

                    if ($LASTEXITCODE -eq 0 -or $bcdOutput -match "correctamente|successfully|created") {
                        Write-Host "        [OK] Archivos de arranque UEFI creados" -ForegroundColor Green
                        $bootRepaired = $true
                        Write-CloneLog "bcdboot UEFI OK: $bcdOutput"
                    } else {
                        Write-Host "        [!] bcdboot: $bcdOutput" -ForegroundColor Yellow
                        Write-CloneLog "bcdboot UEFI resultado: $bcdOutput"
                    }
                } catch {
                    Write-Host "        [ERROR] bcdboot: $($_.Exception.Message)" -ForegroundColor Red
                }

                # Quitar letra de la EFI (debe estar oculta)
                Write-Host "  [2/3] Ocultando particion EFI..." -ForegroundColor Gray
                try {
                    $efiPart = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter -eq $script:DstEfiLetter }
                    if ($efiPart) {
                        Remove-PartitionAccessPath -DiskNumber $DestDisk -PartitionNumber $efiPart.PartitionNumber -AccessPath "$($script:DstEfiLetter):\" -ErrorAction SilentlyContinue
                        Write-Host "        OK" -ForegroundColor Green
                    }
                } catch {}

            } else {
                # ============================================================
                # BCDBOOT PARA MBR/BIOS
                # ============================================================
                Write-Host "        Modo: MBR/BIOS" -ForegroundColor Gray
                Write-CloneLog "Ejecutando bcdboot BIOS: Windows=$winDstLetter"

                $bcdbootCmd = "bcdboot ${winDstLetter}:\Windows /s ${winDstLetter}: /f BIOS /l es-ES"
                Write-Host "        Comando: $bcdbootCmd" -ForegroundColor DarkGray

                try {
                    $bcdResult = & cmd /c $bcdbootCmd 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "        [OK] Archivos de arranque BIOS creados" -ForegroundColor Green
                        $bootRepaired = $true
                    }
                } catch {}

                # Marcar particion como activa (MBR)
                Write-Host "  [2/3] Marcando particion como activa..." -ForegroundColor Gray
                try {
                    $winPart = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter -eq $winDstLetter }
                    if ($winPart) {
                        Set-Partition -DiskNumber $DestDisk -PartitionNumber $winPart.PartitionNumber -IsActive $true -ErrorAction SilentlyContinue
                        Write-Host "        OK" -ForegroundColor Green
                    }
                } catch {}
            }
        } else {
            Write-Host "        [!] No se encontro particion de Windows" -ForegroundColor Yellow
            # Intentar reparacion generica
            $bootRepaired = Repair-BootLoader -DiskNumber $DestDisk
        }
    } else {
        Write-Host "  [1/2] Disco de datos (no requiere bootloader)" -ForegroundColor Gray
        $bootRepaired = $true
    }

    if ($bootRepaired) {
        Write-Host "        Disco configurado correctamente" -ForegroundColor Green
    } else {
        Write-Host "        [!] Puede requerir reparacion manual del arranque" -ForegroundColor Yellow
    }

    Write-Host "  [3/3] Limpiando temporales..." -ForegroundColor Gray
    Remove-Item -Path $wimFolder -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "        OK" -ForegroundColor Green

    Enable-FormatPopups

    # =========================================================================
    # RESUMEN FINAL HIBRIDO (usuario + tecnico)
    # =========================================================================
    $duration = (Get-Date) - $startTime
    $durationMin = [math]::Floor($duration.TotalMinutes)
    $durationSec = $duration.Seconds
    $durationStr = if ($durationMin -gt 0) { "$durationMin min $durationSec seg" } else { "$durationSec segundos" }
    $totalGB = [math]::Round($totalUsedBytes / 1GB, 1)
    $avgSpeedTotal = [math]::Round(($totalUsedBytes / 1MB) / $duration.TotalSeconds, 1)

    # Nombres de discos para el resumen
    $srcDiskName = $src.FriendlyName
    if ($srcDiskName.Length -gt 30) { $srcDiskName = $srcDiskName.Substring(0, 27) + "..." }
    $dstDiskName = $dst.FriendlyName
    if ($dstDiskName.Length -gt 30) { $dstDiskName = $dstDiskName.Substring(0, 27) + "..." }

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║              ✓ CLONADO COMPLETADO CON EXITO                       ║" -ForegroundColor Green
    Write-Host "  ╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║                                                                   ║" -ForegroundColor Green
    Write-Host "  ║  Tu disco ha sido clonado exitosamente.                           ║" -ForegroundColor White
    Write-Host "  ║  Ya puedes guardar el disco como reemplazo del original.          ║" -ForegroundColor White
    Write-Host "  ║  Mantenlo en un lugar seguro por si falla el original algun dia.  ║" -ForegroundColor Gray
    Write-Host "  ║                                                                   ║" -ForegroundColor Green
    Write-Host "  ╟───────────────────────────────────────────────────────────────────╢" -ForegroundColor Green
    Write-Host "  ║  DETALLES TECNICOS:                                               ║" -ForegroundColor DarkGray
    Write-Host "  ║                                                                   ║" -ForegroundColor Green
    Write-Host "  ║  • Origen:  Disco $SourceDisk ($($srcDiskName.PadRight(35)))║" -ForegroundColor Gray
    Write-Host "  ║  • Destino: Disco $DestDisk ($($dstDiskName.PadRight(35)))║" -ForegroundColor Gray
    Write-Host "  ║  • Datos transferidos: $($totalGB.ToString().PadRight(6)) GB                             ║" -ForegroundColor Cyan
    Write-Host "  ║  • Velocidad media:    $($avgSpeedTotal.ToString().PadRight(6)) MB/s                          ║" -ForegroundColor Cyan
    Write-Host "  ║  • Tiempo total:       $($durationStr.PadRight(20))                  ║" -ForegroundColor Gray
    Write-Host "  ║  • Particiones:        $($dstLetters.Count) clonadas                              ║" -ForegroundColor Gray
    if ($isBootable) {
    Write-Host "  ║  • Bootloader:         Configurado ✓                              ║" -ForegroundColor Green
    }
    Write-Host "  ║  • Metodo:             WIMLIB v1.14.4 + VSS                       ║" -ForegroundColor DarkGray
    Write-Host "  ║                                                                   ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Stop-CloneLog -Success $true
    Write-CloneLog "RESUMEN: $totalGB GB en $durationStr ($avgSpeedTotal MB/s)"

    # Actualizar Monitor JSON como completado
    Update-Monitor -Etapa "COMPLETADO" -Progreso 100 -ProgresoGlobal 100 `
        -TiempoTranscurrido $durationStr -BytesCopiadosGB $totalGB -BytesTotalGB $totalGB `
        -Terminado -Log "Clonado completado exitosamente"

    # Ladrido de Nala
    $barkPath = Join-Path $PSScriptRoot "sounds\bark.wav"
    if (Test-Path $barkPath) {
        try {
            $player = New-Object System.Media.SoundPlayer $barkPath
            $player.PlaySync()
            Start-Sleep -Milliseconds 250
            $player.PlaySync()
        } catch {}
    }

    return $true
}

# ===============================================================================
# CLONAR DISCO COMPLETO (TODAS LAS PARTICIONES - PLAN B)
# Clona EFI, MSR, Recovery, Windows - TODO exactamente igual
# ===============================================================================

function Copy-DiskComplete {
    <#
    .SYNOPSIS
        Clona un disco completo incluyendo TODAS las particiones (EFI, MSR, Recovery, etc.)
    .DESCRIPTION
        A diferencia de Copy-DiskFast que solo clona particiones con letra,
        esta funcion clona TODAS las particiones del disco origen,
        asignando letras temporales cuando es necesario.
    #>
    param(
        [int]$SourceDisk,
        [int]$DestDisk
    )

    # =========================================================================
    # CABECERA
    # =========================================================================
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║           CLONADO COMPLETO v2.3 (TODAS LAS PARTICIONES)           ║" -ForegroundColor Cyan
    Write-Host "  ║           Clona EFI + MSR + Recovery + Windows                    ║" -ForegroundColor White
    Write-Host "  ║                                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║           [ESC] o [Q] para cancelar en cualquier momento          ║" -ForegroundColor DarkGray
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # VERIFICACION INICIAL
    if (-not (Test-DiskConnected -DiskNumber $SourceDisk -Nombre "Disco origen")) { return $false }
    if (-not (Test-DiskConnected -DiskNumber $DestDisk -Nombre "Disco destino")) { return $false }

    $srcDisk = Get-Disk -Number $SourceDisk
    $dstDisk = Get-Disk -Number $DestDisk

    # Mostrar info de discos
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ ORIGEN:  [$SourceDisk] $($srcDisk.FriendlyName.PadRight(45).Substring(0,45)) │" -ForegroundColor White
    Write-Host "  │          $("$([math]::Round($srcDisk.Size/1GB, 1)) GB - $($srcDisk.PartitionStyle)".PadRight(56)) │" -ForegroundColor Gray
    Write-Host "  │ DESTINO: [$DestDisk] $($dstDisk.FriendlyName.PadRight(45).Substring(0,45)) │" -ForegroundColor White
    Write-Host "  │          $("$([math]::Round($dstDisk.Size/1GB, 1)) GB".PadRight(56)) │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    # =========================================================================
    # ENUMERAR TODAS LAS PARTICIONES DEL ORIGEN
    # =========================================================================
    Write-Host "  ANALIZANDO DISCO ORIGEN..." -ForegroundColor Yellow
    Write-Host ""

    $allPartitions = Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue |
                     Where-Object { $_.Size -gt 1MB } |
                     Sort-Object PartitionNumber

    if (-not $allPartitions -or $allPartitions.Count -eq 0) {
        Write-Host "  [ERROR] No se encontraron particiones en el disco origen" -ForegroundColor Red
        return $false
    }

    # Clasificar particiones
    $partitionPlan = @()
    $totalDataSize = 0

    foreach ($part in $allPartitions) {
        $partInfo = @{
            Number = $part.PartitionNumber
            Size = $part.Size
            Type = $part.Type
            GptType = $part.GptType
            Letter = $part.DriveLetter
            TempLetter = $null
            FileSystem = "NTFS"
            Label = ""
            Category = "DATA"
        }

        # Detectar tipo de particion
        if ($part.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -or $part.Type -eq "System") {
            $partInfo.Category = "EFI"
            $partInfo.FileSystem = "FAT32"
            $partInfo.Label = "System"
        }
        elseif ($part.GptType -eq "{e3c9e316-0b5c-4db8-817d-f92df00215ae}" -or $part.Type -eq "Reserved") {
            $partInfo.Category = "MSR"
            $partInfo.FileSystem = "NONE"
            $partInfo.Label = ""
        }
        elseif ($part.GptType -eq "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}" -or $part.Type -eq "Recovery") {
            $partInfo.Category = "RECOVERY"
            $partInfo.FileSystem = "NTFS"
            $partInfo.Label = "Recovery"
        }
        else {
            $partInfo.Category = "DATA"
            $partInfo.FileSystem = "NTFS"
            # Detectar si es Windows
            if ($part.DriveLetter) {
                if (Test-Path "$($part.DriveLetter):\Windows\System32\config") {
                    $partInfo.Category = "WINDOWS"
                    $partInfo.Label = "Windows"
                }
            }
        }

        # Calcular espacio usado
        if ($part.DriveLetter) {
            try {
                $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
                if ($vol) {
                    $partInfo.UsedSize = $vol.Size - $vol.SizeRemaining
                    $totalDataSize += $partInfo.UsedSize
                }
            } catch {}
        } else {
            $partInfo.UsedSize = $part.Size
            $totalDataSize += $part.Size
        }

        $partitionPlan += $partInfo

        # Mostrar info
        $sizeStr = "$([math]::Round($part.Size/1MB)) MB"
        if ($part.Size -gt 1GB) { $sizeStr = "$([math]::Round($part.Size/1GB, 1)) GB" }
        $letterStr = if ($part.DriveLetter) { "[$($part.DriveLetter):]" } else { "[--]" }
        $color = switch ($partInfo.Category) {
            "EFI" { "Cyan" }
            "MSR" { "DarkGray" }
            "RECOVERY" { "Yellow" }
            "WINDOWS" { "Green" }
            default { "White" }
        }
        Write-Host "    $letterStr Particion $($part.PartitionNumber): $($partInfo.Category.PadRight(10)) $($sizeStr.PadLeft(10)) $($partInfo.FileSystem)" -ForegroundColor $color
    }

    Write-Host ""
    Write-Host "  TOTAL: $($partitionPlan.Count) particiones, $([math]::Round($totalDataSize/1GB, 1)) GB de datos" -ForegroundColor White
    Write-Host ""

    # Verificar espacio en destino
    if ($dstDisk.Size -lt $totalDataSize) {
        Write-Host "  [ERROR] Disco destino muy pequeno ($([math]::Round($dstDisk.Size/1GB, 1)) GB < $([math]::Round($totalDataSize/1GB, 1)) GB)" -ForegroundColor Red
        return $false
    }

    # DOBLE CONFIRMACION
    $srcName = if ($srcDisk.FriendlyName.Length -gt 30) { $srcDisk.FriendlyName.Substring(0,27) + "..." } else { $srcDisk.FriendlyName }
    $dstName = if ($dstDisk.FriendlyName.Length -gt 30) { $dstDisk.FriendlyName.Substring(0,27) + "..." } else { $dstDisk.FriendlyName }
    $actionDesc = "CLONAR COMPLETO disco $SourceDisk ($srcName) a disco $DestDisk ($dstName)"
    $targetDesc = "Disco $DestDisk - $dstName ($([math]::Round($dstDisk.Size/1GB, 1)) GB)"

    if (-not (Confirm-CriticalAction -Action $actionDesc -Keyword "CLONAR" -TargetName $targetDesc -DangerLevel "danger")) {
        return $false
    }

    # Crear log
    Start-CloneLog -Operation "Clonado Completo" -Source "Disco $SourceDisk" -Destination "Disco $DestDisk"
    $startTime = Get-Date

    # =========================================================================
    # FRASES MOTIVACIONALES Y COLORES CMYK
    # =========================================================================
    $script:frasesClonado = @(
        "Clonanding...",
        "Copianding...",
        "Movending...",
        "Traballanding...",
        "Procesanding...",
        "Analizanding...",
        "Calculanding...",
        "Nalanding...",
        "Gatoanding...",
        "Esperanding...",
        "Optimizanding...",
        "Preparanding...",
        "Sincronizanding..."
    )
    # Colores CMYK (Cyan, Magenta, Yellow, blacK/Gray)
    $script:coloresCMYK = @("Cyan", "Magenta", "Yellow", "Gray")
    $script:colorIndex = 0
    # Spinner rotativo estilo Claude Code: + * - +
    $script:spinnerChars = @('+', '*', '-', '+')
    $script:spinnerIndex = 0
    $script:fraseActual = $script:frasesClonado | Get-Random
    $script:ultimoCambioFrase = Get-Date

    # =========================================================================
    # PRE-SCAN: CONTAR ARCHIVOS TOTALES
    # =========================================================================
    Write-Host ""
    Write-Host "  PRE-SCAN: Contando archivos..." -ForegroundColor Cyan

    $script:totalArchivos = 0
    $script:archivosPorParticion = @{}

    foreach ($partInfo in $partitionPlan) {
        if ($partInfo.Category -eq "MSR") { continue }

        $letter = $null
        $srcPart = Get-Partition -DiskNumber $SourceDisk -PartitionNumber $partInfo.PartNum -ErrorAction SilentlyContinue
        if ($srcPart -and $srcPart.DriveLetter) {
            $letter = $srcPart.DriveLetter
        }

        if ($letter) {
            Write-Host "    Escaneando ${letter}:\ ..." -NoNewline -ForegroundColor Gray
            try {
                # Conteo rapido con cmd dir (mas rapido que Get-ChildItem)
                $countResult = & cmd /c "dir /s /b /a-d `"${letter}:\`" 2>nul | find /c /v `"`""
                $fileCount = [int]$countResult.Trim()
                $script:archivosPorParticion[$partInfo.PartNum] = $fileCount
                $script:totalArchivos += $fileCount
                Write-Host " $fileCount archivos" -ForegroundColor White
            } catch {
                $script:archivosPorParticion[$partInfo.PartNum] = 0
                Write-Host " (no contado)" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
    Write-Host "  TOTAL: " -NoNewline -ForegroundColor White
    Write-Host "$($script:totalArchivos) archivos" -ForegroundColor Cyan
    Write-Host "  a clonar en $($partitionPlan.Count) particiones" -ForegroundColor Gray
    Write-Host ""

    # Variables de progreso global
    $script:archivosCopiados = 0
    $script:bytesCopiados = 0
    $script:particionActual = 0
    $script:totalParticiones = ($partitionPlan | Where-Object { $_.Category -ne "MSR" }).Count

    # Suprimir popups
    Disable-FormatPopups

    # =========================================================================
    # FASE 1: PREPARAR DISCO DESTINO
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 1/3: PREPARANDO DISCO DESTINO" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    try {
        Write-Host "  [1/2] Limpiando disco $DestDisk..." -ForegroundColor Gray
        Clear-Disk -Number $DestDisk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green

        Write-Host "  [2/2] Inicializando como $($srcDisk.PartitionStyle)..." -ForegroundColor Gray
        Initialize-Disk -Number $DestDisk -PartitionStyle $srcDisk.PartitionStyle -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green
        Write-CloneLog "Disco destino inicializado como $($srcDisk.PartitionStyle)"
    } catch {
        Write-Host "  [ERROR] Preparando disco: $_" -ForegroundColor Red
        Enable-FormatPopups
        Stop-CloneLog -Success $false
        return $false
    }

    # =========================================================================
    # FASE 2: CLONAR CADA PARTICION
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 2/3: CLONANDO PARTICIONES" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $availableLetters = @('J','K','N','O','P','Q','R','S','T','U','V','W') | Where-Object { -not (Test-Path "${_}:\") }
    $letterIndex = 0
    $dstPartitions = @()
    $windowsLetter = $null
    $efiLetter = $null

    # ─────────────────────────────────────────────────────────────────────────
    # PROTECCION ANTI-LISTILLOS: Bloquear letras que vamos a usar
    # ─────────────────────────────────────────────────────────────────────────
    $lettersToProtect = $availableLetters | Select-Object -First ($partitionPlan.Count * 2)
    Protect-CloneDrives -DriveLetters $lettersToProtect

    foreach ($partInfo in $partitionPlan) {
        $partNum = $partInfo.Number
        Write-Host ""
        Write-Host "  [$partNum/$($partitionPlan.Count)] $($partInfo.Category): $([math]::Round($partInfo.Size/1MB)) MB" -ForegroundColor White

        # -----------------------------------------------------------------
        # PASO A: Asignar letra temporal al origen si no tiene
        # -----------------------------------------------------------------
        $srcLetter = $partInfo.Letter
        $needRemoveSrcLetter = $false

        if (-not $srcLetter -and $partInfo.Category -ne "MSR") {
            if ($letterIndex -lt $availableLetters.Count) {
                $srcLetter = $availableLetters[$letterIndex]
                $letterIndex++
                try {
                    Add-PartitionAccessPath -DiskNumber $SourceDisk -PartitionNumber $partNum -AccessPath "${srcLetter}:\" -ErrorAction Stop
                    Start-Sleep -Milliseconds 250
                    $needRemoveSrcLetter = $true
                    Write-Host "        Letra temporal origen: ${srcLetter}:" -ForegroundColor DarkGray
                } catch {
                    Write-Host "        [!] No se pudo asignar letra al origen: $_" -ForegroundColor Yellow
                    $srcLetter = $null
                }
            }
        }

        # -----------------------------------------------------------------
        # PASO B: Crear particion en destino
        # -----------------------------------------------------------------
        $dstLetter = $null
        $dstPartNum = $null

        try {
            switch ($partInfo.Category) {
                "EFI" {
                    # Crear EFI con diskpart
                    $sizeMB = [math]::Ceiling($partInfo.Size / 1MB)
                    $dstLetter = $availableLetters[$letterIndex]
                    $letterIndex++

                    $dpScript = @"
select disk $DestDisk
create partition efi size=$sizeMB
format quick fs=fat32 label="System"
assign letter=$dstLetter
"@
                    $dpFile = "$env:TEMP\dp_efi_$partNum.txt"
                    $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
                    & diskpart /s $dpFile 2>&1 | Out-Null
                    Remove-Item $dpFile -Force -ErrorAction SilentlyContinue

                    $efiLetter = $dstLetter
                    Write-Host "        Creada EFI (FAT32) -> ${dstLetter}:" -ForegroundColor Cyan
                }
                "MSR" {
                    # Crear MSR con diskpart (sin letra)
                    $sizeMB = [math]::Ceiling($partInfo.Size / 1MB)
                    $dpScript = @"
select disk $DestDisk
create partition msr size=$sizeMB
"@
                    $dpFile = "$env:TEMP\dp_msr_$partNum.txt"
                    $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
                    & diskpart /s $dpFile 2>&1 | Out-Null
                    Remove-Item $dpFile -Force -ErrorAction SilentlyContinue

                    Write-Host "        Creada MSR ($sizeMB MB)" -ForegroundColor DarkGray
                }
                "RECOVERY" {
                    # Crear Recovery con PowerShell
                    $dstLetter = $availableLetters[$letterIndex]
                    $letterIndex++

                    $isLast = ($partInfo -eq $partitionPlan[-1])
                    if ($isLast) {
                        $newPart = New-Partition -DiskNumber $DestDisk -UseMaximumSize -DriveLetter $dstLetter -ErrorAction Stop
                    } else {
                        $newPart = New-Partition -DiskNumber $DestDisk -Size $partInfo.Size -DriveLetter $dstLetter -ErrorAction Stop
                    }
                    Format-Volume -DriveLetter $dstLetter -FileSystem NTFS -NewFileSystemLabel "Recovery" -Force -Confirm:$false | Out-Null

                    # Marcar como Recovery con diskpart
                    $dstPartNum = $newPart.PartitionNumber
                    $dpScript = @"
select disk $DestDisk
select partition $dstPartNum
set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac override
"@
                    $dpFile = "$env:TEMP\dp_rec_$partNum.txt"
                    $dpScript | Out-File -FilePath $dpFile -Encoding ASCII
                    & diskpart /s $dpFile 2>&1 | Out-Null
                    Remove-Item $dpFile -Force -ErrorAction SilentlyContinue

                    Write-Host "        Creada Recovery (NTFS) -> ${dstLetter}:" -ForegroundColor Yellow
                }
                default {
                    # DATA o WINDOWS - crear particion NTFS normal
                    $dstLetter = $availableLetters[$letterIndex]
                    $letterIndex++

                    $isLast = ($partInfo -eq $partitionPlan[-1])
                    if ($isLast) {
                        $newPart = New-Partition -DiskNumber $DestDisk -UseMaximumSize -DriveLetter $dstLetter -ErrorAction Stop
                    } else {
                        $newPart = New-Partition -DiskNumber $DestDisk -Size $partInfo.Size -DriveLetter $dstLetter -ErrorAction Stop
                    }

                    $label = if ($partInfo.Category -eq "WINDOWS") { "Windows" } else { "Data" }
                    Format-Volume -DriveLetter $dstLetter -FileSystem NTFS -NewFileSystemLabel $label -Force -Confirm:$false | Out-Null

                    if ($partInfo.Category -eq "WINDOWS") {
                        $windowsLetter = $dstLetter
                    }

                    Write-Host "        Creada $($partInfo.Category) (NTFS) -> ${dstLetter}:" -ForegroundColor Green
                }
            }

            $dstPartitions += @{ SrcLetter = $srcLetter; DstLetter = $dstLetter; Category = $partInfo.Category; Size = $partInfo.Size }

        } catch {
            Write-Host "        [ERROR] Creando particion: $_" -ForegroundColor Red
            Write-CloneLog "ERROR creando particion ${partNum}: $_"
        }

        # -----------------------------------------------------------------
        # PASO C: Copiar contenido
        # -----------------------------------------------------------------
        if ($srcLetter -and $dstLetter -and $partInfo.Category -ne "MSR") {
            Write-Host "        Copiando ${srcLetter}: -> ${dstLetter}: ..." -ForegroundColor Gray
            $copyStart = Get-Date

            try {
                if ($partInfo.FileSystem -eq "FAT32") {
                    # EFI: usar robocopy
                    $robocopyArgs = @(
                        "${srcLetter}:\"
                        "${dstLetter}:\"
                        "/MIR"
                        "/R:1", "/W:1"
                        "/NFL", "/NDL", "/NJH", "/NJS", "/NP"
                    )
                    $result = & robocopy @robocopyArgs 2>&1
                    Write-Host "        [OK] EFI copiada (robocopy)" -ForegroundColor Cyan
                } else {
                    # NTFS: usar WIMLIB (captura + aplica) con PROGRESO EN TIEMPO REAL
                    $wimlib = $script:CONFIG.WimlibPath
                    $wimTemp = "$env:TEMP\CLONADISCOS_part${partNum}.wim"
                    $wimFolder = "$env:TEMP\CLONADISCOS_WIM"
                    if (-not (Test-Path $wimFolder)) { New-Item -Path $wimFolder -ItemType Directory -Force | Out-Null }

                    # Eliminar WIM temporal si existe
                    if (Test-Path $wimTemp) { Remove-Item $wimTemp -Force }

                    # Espacio usado del origen (para calcular %)
                    $srcUsedBytes = $partInfo.UsedSize
                    if ($srcUsedBytes -eq 0) { $srcUsedBytes = $partInfo.Size }
                    $srcUsedGB = [math]::Round($srcUsedBytes / 1GB, 1)
                    $archivosParticion = $script:archivosPorParticion[$partNum]
                    if (-not $archivosParticion) { $archivosParticion = 0 }

                    # ─────────────────────────────────────────────────────────────
                    # FASE A: CAPTURA con progreso
                    # ─────────────────────────────────────────────────────────────
                    Write-Host ""
                    Write-Host "        ┌─ CAPTURANDO ${srcLetter}:\ ($srcUsedGB GB, $archivosParticion archivos)" -ForegroundColor Yellow

                    # EJECUTAR WIMLIB DIRECTAMENTE (sin redireccion - la redireccion rompe wimlib)
                    $captureArgsArray = @("capture", "${srcLetter}:\", $wimTemp, "Particion_${partNum}", "--compress=none", "--no-acls")
                    $captureStart = Get-Date

                    Write-CloneLog "Capture: $wimlib $($captureArgsArray -join ' ')"
                    $procCap = Start-Process -FilePath $wimlib -ArgumentList $captureArgsArray -NoNewWindow -Wait -PassThru
                    $captureExitCode = $procCap.ExitCode

                    $captureTime = (Get-Date) - $captureStart
                    Write-Host ""
                    Write-Host "        └─ Capturado en $([math]::Round($captureTime.TotalSeconds)) seg" -ForegroundColor Cyan

                    if ($captureExitCode -ne 0 -or -not (Test-Path $wimTemp)) {
                        throw "wimlib capture fallo (codigo $captureExitCode)"
                    }

                    # ─────────────────────────────────────────────────────────────
                    # FASE B: APLICACION con progreso
                    # ─────────────────────────────────────────────────────────────
                    Write-Host ""
                    Write-Host "        ┌─ APLICANDO a ${dstLetter}:\" -ForegroundColor Yellow

                    # EJECUTAR WIMLIB DIRECTAMENTE (sin redireccion - la redireccion rompe wimlib)
                    $applyArgsArray = @("apply", $wimTemp, "1", "${dstLetter}:\", "--no-acls")
                    $applyStart = Get-Date

                    Write-CloneLog "Apply: $wimlib $($applyArgsArray -join ' ')"
                    $procApp = Start-Process -FilePath $wimlib -ArgumentList $applyArgsArray -NoNewWindow -Wait -PassThru
                    $applyExitCode = $procApp.ExitCode

                    $applyTime = (Get-Date) - $applyStart
                    Write-Host ""

                    if ($applyExitCode -ne 0) {
                        throw "wimlib apply fallo (codigo $applyExitCode)"
                    }

                    # Limpiar WIM temporal
                    Remove-Item $wimTemp -Force -ErrorAction SilentlyContinue

                    $copyTime = (Get-Date) - $copyStart
                    $speedMB = [math]::Round(($partInfo.Size / 1MB) / $copyTime.TotalSeconds, 1)

                    Write-Host "        └─ [OK] Particion clonada en $([math]::Round($copyTime.TotalSeconds)) seg ($speedMB MB/s)" -ForegroundColor Green

                    # Actualizar contadores globales
                    $script:archivosCopiados += $archivosParticion
                    $script:bytesCopiados += $partInfo.UsedSize
                }

                Write-CloneLog "Particion $partNum copiada: $($partInfo.Category)"

            } catch {
                Write-Host "        [ERROR] Copiando: $_" -ForegroundColor Red
                Write-CloneLog "ERROR copiando particion ${partNum}: $_"
            }
        }

        # -----------------------------------------------------------------
        # PASO D: Quitar letra temporal del origen
        # -----------------------------------------------------------------
        if ($needRemoveSrcLetter -and $srcLetter) {
            try {
                Remove-PartitionAccessPath -DiskNumber $SourceDisk -PartitionNumber $partNum -AccessPath "${srcLetter}:\" -ErrorAction SilentlyContinue
            } catch {}
        }
    }

    # =========================================================================
    # FASE 3: CONFIGURAR BOOTLOADER
    # =========================================================================
    Write-Host ""
    Write-Host "  FASE 3/3: CONFIGURANDO BOOTLOADER" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""

    $bootOK = $false

    if ($windowsLetter) {
        if ($srcDisk.PartitionStyle -eq "GPT" -and $efiLetter) {
            Write-Host "  Modo: GPT/UEFI" -ForegroundColor Cyan
            Write-Host "  Windows: ${windowsLetter}:\" -ForegroundColor Gray
            Write-Host "  EFI: ${efiLetter}:\" -ForegroundColor Gray

            $bcdbootCmd = "bcdboot ${windowsLetter}:\Windows /s ${efiLetter}: /f UEFI /l es-ES"
            Write-Host "  Comando: $bcdbootCmd" -ForegroundColor DarkGray

            try {
                $result = & cmd /c $bcdbootCmd 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  [OK] Bootloader UEFI configurado" -ForegroundColor Green
                    $bootOK = $true
                } else {
                    Write-Host "  [!] bcdboot: $result" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [ERROR] bcdboot: $_" -ForegroundColor Red
            }

            # Ocultar EFI
            Write-Host "  Ocultando particion EFI..." -ForegroundColor Gray
            try {
                $efiPart = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter -eq $efiLetter }
                if ($efiPart) {
                    Remove-PartitionAccessPath -DiskNumber $DestDisk -PartitionNumber $efiPart.PartitionNumber -AccessPath "${efiLetter}:\" -ErrorAction SilentlyContinue
                    Write-Host "  OK" -ForegroundColor Green
                }
            } catch {}

        } else {
            Write-Host "  Modo: MBR/BIOS" -ForegroundColor Gray
            $bcdbootCmd = "bcdboot ${windowsLetter}:\Windows /s ${windowsLetter}: /f BIOS /l es-ES"
            Write-Host "  Comando: $bcdbootCmd" -ForegroundColor DarkGray

            try {
                $result = & cmd /c $bcdbootCmd 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  [OK] Bootloader BIOS configurado" -ForegroundColor Green
                    $bootOK = $true

                    # Marcar como activa
                    $winPart = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter -eq $windowsLetter }
                    if ($winPart) {
                        Set-Partition -DiskNumber $DestDisk -PartitionNumber $winPart.PartitionNumber -IsActive $true -ErrorAction SilentlyContinue
                    }
                }
            } catch {}
        }
    } else {
        Write-Host "  [!] No se detecto particion Windows - disco de datos" -ForegroundColor Yellow
        $bootOK = $true
    }

    # =========================================================================
    # LIMPIAR LETRAS TEMPORALES DEL DESTINO
    # =========================================================================
    Write-Host ""
    Write-Host "  Limpiando letras temporales..." -ForegroundColor Gray
    foreach ($dp in $dstPartitions) {
        if ($dp.DstLetter -and $dp.Category -notin @("WINDOWS", "DATA")) {
            try {
                $part = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter -eq $dp.DstLetter }
                if ($part) {
                    Remove-PartitionAccessPath -DiskNumber $DestDisk -PartitionNumber $part.PartitionNumber -AccessPath "$($dp.DstLetter):\" -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }

    Enable-FormatPopups

    # =========================================================================
    # RESTAURAR ACCESO A UNIDADES
    # =========================================================================
    Unprotect-CloneDrives

    # =========================================================================
    # RESUMEN FINAL
    # =========================================================================
    $duration = (Get-Date) - $startTime
    $durationStr = "{0:hh\:mm\:ss}" -f $duration
    $totalGB = [math]::Round($totalDataSize / 1GB, 1)

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║                    CLONADO COMPLETO FINALIZADO                    ║" -ForegroundColor Green
    Write-Host "  ╠═══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "  ║  Particiones clonadas: $($partitionPlan.Count.ToString().PadRight(43)) ║" -ForegroundColor White
    Write-Host "  ║  Datos copiados:       $("$totalGB GB".PadRight(43)) ║" -ForegroundColor White
    Write-Host "  ║  Tiempo total:         $($durationStr.PadRight(43)) ║" -ForegroundColor White
    Write-Host "  ║  Bootloader:           $(if ($bootOK) { "OK".PadRight(43) } else { "Requiere revision".PadRight(43) }) ║" -ForegroundColor $(if ($bootOK) { "Green" } else { "Yellow" })
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    Stop-CloneLog -Success $bootOK
    Write-CloneLog "RESUMEN: $($partitionPlan.Count) particiones, $totalGB GB en $durationStr"

    # Ladrido de Nala
    $barkPath = Join-Path $PSScriptRoot "sounds\bark.wav"
    if (Test-Path $barkPath) {
        try {
            $player = New-Object System.Media.SoundPlayer $barkPath
            $player.PlaySync()
            Start-Sleep -Milliseconds 250
            $player.PlaySync()
        } catch {}
    }

    # =========================================================================
    # EXPULSION SEGURA DE DISCOS
    # =========================================================================
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  ¿Quieres expulsar los discos de forma segura?                  │" -ForegroundColor White
    Write-Host "  │                                                                 │" -ForegroundColor Cyan
    Write-Host "  │  [S] Si, expulsar ambos discos (origen y destino)               │" -ForegroundColor Green
    Write-Host "  │  [D] Solo el disco DESTINO (clonado)                            │" -ForegroundColor Yellow
    Write-Host "  │  [N] No, dejarlo conectado                                      │" -ForegroundColor Gray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Opcion [S/D/N]: " -NoNewline -ForegroundColor White
    $ejectOption = Read-Host

    if ($ejectOption -match "^[Ss]$") {
        # Expulsar ambos discos
        Write-Host ""
        Write-Host "  Expulsando discos de forma segura..." -ForegroundColor Cyan

        # Expulsar disco destino
        $dstDiskObj = Get-Disk -Number $DestDisk -ErrorAction SilentlyContinue
        if ($dstDiskObj) {
            try {
                # Quitar todas las letras del disco destino
                Get-Partition -DiskNumber $DestDisk -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DriveLetter) {
                        $letter = $_.DriveLetter
                        # Flush buffers
                        & cmd /c "fsutil volume flush ${letter}:" 2>$null
                        Start-Sleep -Milliseconds 200
                    }
                }
                # Poner offline
                Set-Disk -Number $DestDisk -IsOffline $true -ErrorAction SilentlyContinue
                Write-Host "    [OK] Disco $DestDisk (destino) expulsado" -ForegroundColor Green
            } catch {
                Write-Host "    [!] No se pudo expulsar disco $DestDisk" -ForegroundColor Yellow
            }
        }

        # Expulsar disco origen
        $srcDiskObj = Get-Disk -Number $SourceDisk -ErrorAction SilentlyContinue
        if ($srcDiskObj) {
            try {
                Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DriveLetter) {
                        $letter = $_.DriveLetter
                        & cmd /c "fsutil volume flush ${letter}:" 2>$null
                        Start-Sleep -Milliseconds 200
                    }
                }
                Set-Disk -Number $SourceDisk -IsOffline $true -ErrorAction SilentlyContinue
                Write-Host "    [OK] Disco $SourceDisk (origen) expulsado" -ForegroundColor Green
            } catch {
                Write-Host "    [!] No se pudo expulsar disco $SourceDisk" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "  Ya puedes desconectar los cables USB de forma segura." -ForegroundColor Green

    } elseif ($ejectOption -match "^[Dd]$") {
        # Solo expulsar disco destino
        Write-Host ""
        Write-Host "  Expulsando disco destino..." -ForegroundColor Cyan

        $dstDiskObj = Get-Disk -Number $DestDisk -ErrorAction SilentlyContinue
        if ($dstDiskObj) {
            try {
                Get-Partition -DiskNumber $DestDisk -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($_.DriveLetter) {
                        $letter = $_.DriveLetter
                        & cmd /c "fsutil volume flush ${letter}:" 2>$null
                        Start-Sleep -Milliseconds 200
                    }
                }
                Set-Disk -Number $DestDisk -IsOffline $true -ErrorAction SilentlyContinue
                Write-Host "    [OK] Disco $DestDisk (destino) expulsado" -ForegroundColor Green
            } catch {
                Write-Host "    [!] No se pudo expulsar disco $DestDisk" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "  Ya puedes desconectar el disco clonado de forma segura." -ForegroundColor Green

    } else {
        Write-Host ""
        Write-Host "  Discos conectados. Recuerda expulsarlos antes de desconectar." -ForegroundColor DarkGray
    }

    Write-Host ""

    return $bootOK
}

# ===============================================================================
# CLONAR DISCO A DISCO (ROBOCOPY - DETALLADO)
# ===============================================================================

function Copy-DiskToDisk {
    param(
        [int]$SourceDisk,
        [int]$DestDisk,
        [switch]$ExcludeWinSxS   # Para backup rápido (NO booteable)
    )

    Write-Host ""
    Write-Host "  [CLONAR DISCO A DISCO]" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray

    # VERIFICACION INICIAL: Ambos discos conectados
    if (-not (Test-DiskConnected -DiskNumber $SourceDisk -Nombre "Disco origen")) { return $false }
    if (-not (Test-DiskConnected -DiskNumber $DestDisk -Nombre "Disco destino")) { return $false }

    $src = Get-Disk -Number $SourceDisk
    $dst = Get-Disk -Number $DestDisk

    Write-Host "  Origen:   [$SourceDisk] $($src.FriendlyName) ($([math]::Round($src.Size/1GB, 1)) GB)" -ForegroundColor White
    Write-Host "  Destino:  [$DestDisk] $($dst.FriendlyName) ($([math]::Round($dst.Size/1GB, 1)) GB)" -ForegroundColor White
    Write-Host ""

    # Obtener TODAS las particiones del origen (incluso sin letra)
    $allSrcPartitions = Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue |
                        Where-Object { $_.Size -gt 1MB -and $_.Type -ne "Reserved" } |
                        Sort-Object PartitionNumber

    if (-not $allSrcPartitions -or $allSrcPartitions.Count -eq 0) {
        Write-Host "  [ERROR] El disco origen no tiene particiones." -ForegroundColor Red
        return $false
    }

    # Mostrar particiones encontradas (con y sin letra)
    Write-Host "  Particiones encontradas en disco origen:" -ForegroundColor Cyan
    $tempLettersAssigned = @()
    $usedLetters = @((Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter)

    foreach ($p in $allSrcPartitions) {
        $tieneLetra = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { "(sin letra)" }
        $tipo = $p.Type
        $sizeGB = [math]::Round($p.Size / 1GB, 2)
        Write-Host "    - Particion $($p.PartitionNumber): $tieneLetra [$tipo] $sizeGB GB" -ForegroundColor Gray

        # Si no tiene letra, asignar una temporal (oculta en Explorer)
        if (-not $p.DriveLetter -and $p.Type -notin @("Reserved", "Unknown")) {
            foreach ($l in [char[]](85..90)) {  # U-Z para temporales
                if ($l -notin $usedLetters) {
                    try {
                        Set-Partition -DiskNumber $SourceDisk -PartitionNumber $p.PartitionNumber -NewDriveLetter $l -ErrorAction Stop
                        Hide-DriveFromExplorer -DriveLetter $l
                        $usedLetters += $l
                        $tempLettersAssigned += @{ DiskNumber = $SourceDisk; PartitionNumber = $p.PartitionNumber; Letter = $l }
                        Write-Host "      -> Asignada letra temporal $l`: (oculta)" -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 250
                        break
                    } catch {
                        # No se pudo asignar, continuar
                    }
                }
            }
        }
    }
    Write-Host ""

    # Ahora obtener particiones con letra (originales + temporales)
    $srcPartitions = Get-Partition -DiskNumber $SourceDisk -ErrorAction SilentlyContinue |
                     Where-Object { $_.DriveLetter } | Sort-Object PartitionNumber

    # Calcular espacio usado total
    $totalUsedGB = 0
    foreach ($p in $srcPartitions) {
        $vol = Get-Volume -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
        if ($vol) {
            $usedGB = [math]::Round(($vol.Size - $vol.SizeRemaining) / 1GB, 1)
            $totalUsedGB += $usedGB
            Write-Host "    $($p.DriveLetter): $usedGB GB usados" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Host "  Total a copiar: $totalUsedGB GB" -ForegroundColor Yellow
    Write-Host ""

    # VERIFICACION DE ESPACIO EN DISCO DESTINO
    $dstSizeGB = [math]::Round($dst.Size / 1GB, 1)
    if ($totalUsedGB -gt $dstSizeGB) {
        Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "    ║                    ERROR: ESPACIO INSUFICIENTE                  ║" -ForegroundColor Red
        Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
        Write-Host "    ║                                                                 ║" -ForegroundColor Red
        Write-Host "    ║  Datos a copiar:    $("{0,8}" -f "$totalUsedGB GB")                                   ║" -ForegroundColor White
        Write-Host "    ║  Disco destino:     $("{0,8}" -f "$dstSizeGB GB")                                   ║" -ForegroundColor White
        Write-Host "    ║  Faltan:            $("{0,8}" -f "$([math]::Round($totalUsedGB - $dstSizeGB, 1)) GB")                                   ║" -ForegroundColor Yellow
        Write-Host "    ║                                                                 ║" -ForegroundColor Red
        Write-Host "    ║  El disco destino es demasiado pequeño para los datos.         ║" -ForegroundColor Gray
        Write-Host "    ║  Usa un disco de mayor capacidad.                              ║" -ForegroundColor Gray
        Write-Host "    ║                                                                 ║" -ForegroundColor Red
        Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        # Limpiar letras temporales antes de salir
        foreach ($temp in $tempLettersAssigned) {
            try {
                Remove-PartitionAccessPath -DiskNumber $temp.DiskNumber -PartitionNumber $temp.PartitionNumber -AccessPath "$($temp.Letter):\" -ErrorAction SilentlyContinue
            } catch {}
        }
        return $false
    } elseif ($totalUsedGB -gt ($dstSizeGB * 0.9)) {
        # Advertencia si queda menos del 10% libre
        $espacioLibre = [math]::Round($dstSizeGB - $totalUsedGB, 1)
        Write-Host "    [AVISO] El disco destino quedara casi lleno ($espacioLibre GB libres)" -ForegroundColor Yellow
        Write-Host ""
    } else {
        Write-Host "    [OK] Espacio en destino: $dstSizeGB GB (suficiente)" -ForegroundColor Green
        Write-Host ""
    }

    Write-Host "  [ADVERTENCIA] Esta operacion BORRARA TODOS LOS DATOS del disco destino!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  ¿Continuar? [S/N]: " -NoNewline -ForegroundColor Yellow
    $continuar = Read-Host
    if ($continuar -notmatch "^[Ss]$") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }
    Write-Host ""
    Write-Host "  Escribe 'CLONAR' para confirmar: " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host

    if ($confirm -ne "CLONAR") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }

    $startTime = Get-Date
    
    # Iniciar LOG automatico
    $srcDiskInfo = Get-Disk -Number $SourceDisk
    $dstDiskInfo = Get-Disk -Number $DestDisk
    Start-CloneLog -Operation "Clonacion Disco a Disco" -Source "Disco $SourceDisk ($([math]::Round($srcDiskInfo.Size/1GB))GB)" -Destination "Disco $DestDisk ($([math]::Round($dstDiskInfo.Size/1GB))GB)"
    Write-CloneLog "Inicio de clonacion - $totalUsedGB GB a copiar"
    
    Write-Host ""
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  INICIANDO CLONACION - NO DESCONECTES LOS DISCOS" -ForegroundColor Yellow
    Write-Host "  ═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  LOG: $script:CurrentLogFile" -ForegroundColor DarkGray
    Write-Host ""

    # Suprimir popups de formateo de Windows
    Write-Host "  Preparando entorno (suprimiendo popups)..." -ForegroundColor Gray
    Disable-FormatPopups

    # Lista para trackear letras ocultas (para restaurar después)
    $hiddenDriveLetters = @()

    # ULTIMA VERIFICACION antes del punto de no retorno
    Write-Host "  Verificando discos antes de continuar..." -ForegroundColor Gray
    if (-not (Test-DiskConnected -DiskNumber $SourceDisk -Nombre "Disco origen")) {
        Enable-FormatPopups
        return $false
    }
    if (-not (Test-DiskConnected -DiskNumber $DestDisk -Nombre "Disco destino")) {
        Enable-FormatPopups
        return $false
    }

    # PASO 1: Limpiar disco destino
    Write-Host "  [1/4] Limpiando disco destino..." -ForegroundColor Cyan
    try {
        Clear-Disk -Number $DestDisk -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green
    } catch {
        Write-Host "        Ya estaba limpio o error: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # PASO 2: Inicializar con mismo estilo de particion
    $partStyle = $src.PartitionStyle
    Write-Host "  [2/4] Inicializando como $partStyle..." -ForegroundColor Cyan
    try {
        Initialize-Disk -Number $DestDisk -PartitionStyle $partStyle -ErrorAction Stop
        Write-Host "        OK" -ForegroundColor Green
    } catch {
        Write-Host "        Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    # PASO 3: Crear particiones y copiar datos una por una
    Write-Host "  [3/4] Creando particiones y copiando datos..." -ForegroundColor Cyan
    Write-Host ""

    # Mostrar barra de progreso global inicial
    Write-Host "  ┌───────────────────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkCyan
    Write-Host "  │  PROGRESO GLOBAL                                                              │" -ForegroundColor DarkCyan
    Write-Host "  └───────────────────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkCyan
    Write-Host ""

    # Obtener letras ya usadas
    $usedLetters = @((Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter)

    # Tracking para progreso global
    $globalCopiedGB = 0
    $totalPartsCount = $srcPartitions.Count

    $partNum = 0
    foreach ($srcPart in $srcPartitions) {
        $partNum++
        $srcLetter = $srcPart.DriveLetter
        $srcVol = Get-Volume -DriveLetter $srcLetter -ErrorAction SilentlyContinue

        if (-not $srcVol) { continue }

        $partSizeGB = [math]::Round($srcPart.Size / 1GB, 1)
        $usedGB = [math]::Round(($srcVol.Size - $srcVol.SizeRemaining) / 1GB, 1)
        $fsLabel = if ($srcVol.FileSystemLabel) { $srcVol.FileSystemLabel } else { "Particion$partNum" }
        $fsType = $srcVol.FileSystem

        Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
        Write-Host "  │ PARTICION $partNum`: $srcLetter`: $fsLabel ($partSizeGB GB, $usedGB GB usados)" -ForegroundColor White
        Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray

        # Crear particion en destino
        Write-Host "    [a] Creando particion..." -ForegroundColor Gray
        try {
            $newPart = New-Partition -DiskNumber $DestDisk -Size $srcPart.Size -ErrorAction Stop
            Write-Host "        OK - Particion creada" -ForegroundColor Green
        } catch {
            Write-Host "        ERROR: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        # Buscar letra libre
        $freeLetter = $null
        foreach ($l in [char[]](70..90)) {  # F-Z
            if ($l -notin $usedLetters) {
                $freeLetter = $l
                $usedLetters += $l
                break
            }
        }

        if (-not $freeLetter) {
            Write-Host "        ERROR: No hay letras de unidad libres" -ForegroundColor Red
            continue
        }

        # Asignar letra (oculta en Explorer)
        Write-Host "    [b] Asignando letra $freeLetter`: (oculta)..." -ForegroundColor Gray
        try {
            Set-Partition -DiskNumber $DestDisk -PartitionNumber $newPart.PartitionNumber -NewDriveLetter $freeLetter -ErrorAction Stop
            # Ocultar de Explorer
            Hide-DriveFromExplorer -DriveLetter $freeLetter
            $hiddenDriveLetters += $freeLetter
            Start-Sleep -Seconds 2
            Write-Host "        OK" -ForegroundColor Green
        } catch {
            Write-Host "        ERROR: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        # Formatear
        Write-Host "    [c] Formateando como $fsType..." -ForegroundColor Gray
        try {
            Format-Volume -DriveLetter $freeLetter -FileSystem $fsType -NewFileSystemLabel $fsLabel -Confirm:$false -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 2
            Write-Host "        OK" -ForegroundColor Green
        } catch {
            Write-Host "        ERROR: $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        # Copiar datos con ROBOCOPY y barra de progreso
        Write-Host "    [d] Copiando $usedGB GB de datos..." -ForegroundColor Yellow
        Write-Host "        $srcLetter`:\ --> $freeLetter`:\" -ForegroundColor Cyan
        Write-Host ""

        # Skip conteo de archivos (muy lento en discos grandes)
        # Contar archivos del origen (una sola vez, antes de copiar)
        Write-Host "        Contando archivos..." -ForegroundColor Gray -NoNewline
        $totalFiles = 0
        try {
            # Conteo rápido sin recurrir a toda la estructura (solo primer nivel + estimación)
            $quickCount = (Get-ChildItem "$srcLetter`:\" -File -ErrorAction SilentlyContinue | Measure-Object).Count
            $dirCount = (Get-ChildItem "$srcLetter`:\" -Directory -ErrorAction SilentlyContinue | Measure-Object).Count
            # Estimación: promedio 500 archivos por carpeta de sistema
            $totalFiles = $quickCount + ($dirCount * 500)
            Write-Host " ~$totalFiles archivos (estimado)" -ForegroundColor DarkGray
        } catch {
            $totalFiles = 50000  # Estimación por defecto
            Write-Host " estimando..." -ForegroundColor DarkGray
        }

        Write-Host "        Iniciando copia..." -ForegroundColor Gray
        Write-Host ""

        # Construir exclusiones
        $excludeDirs = @("System Volume Information", "`$Recycle.Bin", "Recovery")
        if ($ExcludeWinSxS) {
            $excludeDirs += "Windows\WinSxS"
            Write-Host "        [!] Modo BACKUP RAPIDO: Excluyendo WinSxS (NO booteable)" -ForegroundColor Yellow
        }

        $robocopyArgs = @(
            "$srcLetter`:\"
            "$freeLetter`:\"
            "/E"
            "/COPY:DAT"
            "/DCOPY:DAT"
            "/R:1"
            "/W:1"
            "/MT:32"
            "/J"
            "/XJ"
            "/XD") + $excludeDirs + @(
            "/XF", "pagefile.sys", "hiberfil.sys", "swapfile.sys"
            "/NP"       # Sin porcentaje por archivo
            "/LOG+:$script:CurrentLogFile"
        )

        # Iniciar robocopy en background
        $robocopyProcess = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -NoNewWindow -PassThru

        # Mostrar progreso mientras copia
        $srcSizeBytes = $usedGB * 1GB
        $copyStartTime = Get-Date
        $lastGlobalUpdate = Get-Date
        $copyWasCancelled = $false
        $filesCopied = 0
        $lastFileCount = 0
        # Para calcular velocidad real (media movil)
        $speedSamples = @()
        $lastDstSize = 0
        $lastSpeedCheck = Get-Date

        # Frases random estilo Claude "thinking" - MAS VARIEDAD
        $frasesRandom = @(
            "Clonanding...", "Traballanding...", "Pensanding...", "Mianding...",
            "Nalanding...", "Ladranding...", "Gatoanding...", "Abejanding...",
            "Analizanding...", "Discocloneanding...", "Clonadiscosanding...",
            "Apuranding...", "Copianding...", "Movending...", "Calculanding...",
            "Esperanding...", "Restauranding...", "Bytesanding...", "Datosanding...",
            "Volanding...", "Sectoranding...", "Bitanding...", "Backupanding...",
            "Flasheanding...", "NVMeanding...", "SSDanding...", "Diskanding...",
            "Particionanding...", "Clonificanding...", "Duplicanding...",
            "Replicanding...", "Mirroreanding...", "Imageanding...", "Capturanding...",
            "Rescatanding...", "Salvanding...", "Preservanding...", "Proteganding...",
            "Zen mode ON", "Cafe pls", "CAFE AHORA", "Zzzzzzz", "So bored",
            "Trust process", "You got this", "Almost there", "Cruza dedos"
        )
        # Colores arcoiris estilo Claude thinking
        $thinkingColors = @("Red", "DarkYellow", "Yellow", "Green", "Cyan", "Blue", "Magenta")
        $colorIndex = 0
        $lastFraseTime = Get-Date
        $currentFrase = $frasesRandom | Get-Random
        $currentColor = $thinkingColors[$colorIndex]
        $script:mostrado99 = $false

        Write-Host "        [ESC] o [Q] para CANCELAR" -ForegroundColor DarkGray
        Write-Host ""

        while (-not $robocopyProcess.HasExited) {
            Start-Sleep -Milliseconds 250

            # DETECTAR CANCELACION
            if (Test-KeyAvailableSafe) {
                $key = Read-TeclaSafe
                if ($key.Key -eq [ConsoleKey]::Escape -or $key.Key -eq [ConsoleKey]::Q) {
                    $copyWasCancelled = $true
                    Write-Host ""
                    Write-Host ""
                    Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
                    Write-Host "    ║                   CANCELANDO COPIA...                           ║" -ForegroundColor Yellow
                    Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow

                    # Matar proceso robocopy
                    try {
                        Stop-Process -Id $robocopyProcess.Id -Force -ErrorAction SilentlyContinue
                    } catch {}

                    break
                }
            }

            # Cambiar frase cada 3 segundos y color cada segundo (mas dinamico)
            if (((Get-Date) - $lastFraseTime).TotalSeconds -ge 3) {
                $currentFrase = $frasesRandom | Get-Random
                $lastFraseTime = Get-Date
            }
            # Rotar color mas rapido (cada segundo)
            $colorIndex = [int]((Get-Date).Second) % $thinkingColors.Count
            $currentColor = $thinkingColors[$colorIndex]

            # Calcular progreso REAL midiendo destino cada 3 segundos
            $elapsed = (Get-Date) - $copyStartTime
            $elapsedStr = "{0:mm\:ss}" -f $elapsed

            # Medir tamaño destino cada 3 segundos (no en cada iteracion)
            $timeSinceLastCheck = ((Get-Date) - $lastSpeedCheck).TotalSeconds
            if ($timeSinceLastCheck -ge 3) {
                try {
                    # Obtener tamaño real del destino (rapido con -Force)
                    $dstSize = (Get-ChildItem -Path $dstPath -Recurse -Force -ErrorAction SilentlyContinue |
                                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                    if (-not $dstSize) { $dstSize = 0 }

                    # Calcular velocidad real (bytes/segundo)
                    if ($lastDstSize -gt 0 -and $timeSinceLastCheck -gt 0) {
                        $deltaBytes = $dstSize - $lastDstSize
                        $instantSpeedMBs = [math]::Round($deltaBytes / $timeSinceLastCheck / 1MB, 1)
                        if ($instantSpeedMBs -gt 0) {
                            $speedSamples += $instantSpeedMBs
                            # Mantener solo ultimas 10 muestras (media movil)
                            if ($speedSamples.Count -gt 10) { $speedSamples = $speedSamples[-10..-1] }
                        }
                    }
                    $lastDstSize = $dstSize
                    $lastSpeedCheck = Get-Date
                } catch {
                    $dstSize = $lastDstSize
                }
            } else {
                $dstSize = $lastDstSize
            }

            if ($srcSizeBytes -gt 0) {
                $pct = [math]::Min(99, [math]::Round(($dstSize / $srcSizeBytes) * 100))  # Max 99% hasta que termine
            } else {
                $pct = 0
            }

            $copiedGB = [math]::Round($dstSize / 1GB, 2)
            # Velocidad: media movil de las muestras o "---" si no hay datos
            $speedMBs = if ($speedSamples.Count -gt 0) {
                [math]::Round(($speedSamples | Measure-Object -Average).Average, 1)
            } else { 0 }
            $speedDisplay = if ($speedMBs -gt 0) { "$speedMBs MB/s" } else { "--- MB/s" }

            # Calcular tiempo restante estimado (solo si hay velocidad medida)
            $remainingBytes = $srcSizeBytes - $dstSize
            $remainingSecs = if ($speedMBs -gt 0) { $remainingBytes / 1MB / $speedMBs } else { 0 }
            $remainingStr = if ($speedMBs -gt 0) { "{0:mm\:ss}" -f [TimeSpan]::FromSeconds($remainingSecs) } else { "--:--" }

            # Dibujar barra de progreso de particion actual
            $barWidth = 40
            $filled = [math]::Floor(($pct / 100) * $barWidth)
            $empty = $barWidth - $filled
            $bar = ("█" * $filled) + ("░" * $empty)

            # Calcular progreso global
            $currentGlobalGB = $globalCopiedGB + $copiedGB
            $globalPct = if ($totalUsedGB -gt 0) { [math]::Min(100, [math]::Round(($currentGlobalGB / $totalUsedGB) * 100)) } else { 0 }
            $globalElapsed = (Get-Date) - $startTime
            $globalElapsedStr = "{0:hh\:mm\:ss}" -f $globalElapsed

            # Timer de particion actual con COLOR segun duracion
            $partElapsed = (Get-Date) - $copyStartTime
            $partSecs = [math]::Floor($partElapsed.TotalSeconds)
            $partTimeStr = "{0:00}:{1:00}" -f [int][math]::Floor($partSecs / 60), [int]($partSecs % 60)
            # Color: gris <30s, amarillo 30-60s, naranja >60s, rojo >120s
            $partTimeColor = "DarkGray"
            if ($partSecs -gt 120) { $partTimeColor = "Red" }
            elseif ($partSecs -gt 60) { $partTimeColor = "DarkYellow" }
            elseif ($partSecs -gt 30) { $partTimeColor = "Yellow" }

            # ETA INTERPOLADO (estilo FREGONATOR) - estima progreso parcial
            $etaGlobal = "--:--"
            if ($globalPct -gt 0 -and $globalElapsed.TotalSeconds -gt 10) {
                $avgSecsPerPct = $globalElapsed.TotalSeconds / $globalPct
                $remainingPct = 100 - $globalPct
                $etaGlobalSecs = $avgSecsPerPct * $remainingPct
                $etaGlobal = "{0:hh\:mm\:ss}" -f [TimeSpan]::FromSeconds([math]::Max(0, $etaGlobalSecs))
            }

            # Linea combinada: progreso global + particion actual + timer con color + frase
            $statusLine = "  GLOBAL: $globalPct% ($([math]::Round($currentGlobalGB,1))/$totalUsedGB GB) $globalElapsedStr ETA:$etaGlobal | PART $partNum`: [$bar] $pct% $speedDisplay "
            Write-Host "`r$statusLine" -NoNewline -ForegroundColor Cyan
            Write-Host "$partTimeStr " -NoNewline -ForegroundColor $partTimeColor
            Write-Host "| " -NoNewline -ForegroundColor Cyan
            Write-Host "$($currentFrase.PadRight(16))" -NoNewline -ForegroundColor $currentColor

            # Actualizar Monitor JSON para GUI externa
            Update-Monitor -Etapa "Copiando particion $partNum" `
                -Progreso $pct -ProgresoGlobal $globalPct `
                -Velocidad $speedMBs -ETA $etaGlobal `
                -TiempoTranscurrido $globalElapsedStr `
                -ArchivoActual $currentFrase `
                -ParticionActual $partNum -ParticionesTotal $totalPartitions `
                -BytesCopiadosGB $currentGlobalGB -BytesTotalGB $totalUsedGB

            # Mostrar archivo actual desde el log (ultima linea con "Nuevo arch")
            # Y contar archivos copiados (cada 2 segundos para no sobrecargar)
            try {
                $lastLine = Get-Content $script:CurrentLogFile -Tail 1 -ErrorAction SilentlyContinue
                if ($lastLine -match "Nuevo arch.*\\([^\\]+)$") {
                    $currentFile = $matches[1]
                    if ($currentFile.Length -gt 50) { $currentFile = "..." + $currentFile.Substring($currentFile.Length - 47) }

                    # Contar archivos copiados (eficiente: solo cada 2 segundos)
                    if (((Get-Date) - $copyStartTime).TotalSeconds % 2 -lt 0.5) {
                        try {
                            $filesCopied = (Select-String -Path $script:CurrentLogFile -Pattern "Nuevo arch" -SimpleMatch -ErrorAction SilentlyContinue | Measure-Object).Count
                        } catch { }
                    }

                    # Mostrar archivo actual + contador
                    $fileCounter = "[$filesCopied/$totalFiles]"
                    Write-Host "`n        $fileCounter -> $($currentFile.PadRight(55))" -NoNewline -ForegroundColor DarkGray
                }
            } catch {}

            # Mensaje especial al llegar al 99% para que el usuario sepa que sigue trabajando
            if ($pct -ge 99 -and -not $script:mostrado99) {
                $script:mostrado99 = $true
                Write-Host ""
                Write-Host ""
                Write-Host "        [i] 99% - Finalizando archivos del sistema... puede tardar unos minutos" -ForegroundColor Yellow
                Write-Host "            No cierres la ventana, sigue copiando archivos pequenos." -ForegroundColor DarkGray
                Write-Host ""
            }
        }

        # Si fue cancelado, limpiar y salir
        if ($copyWasCancelled) {
            Write-Host ""
            Write-Host ""
            # Limpiar letras temporales
            foreach ($temp in $tempLettersAssigned) {
                try {
                    Remove-PartitionAccessPath -DiskNumber $temp.DiskNumber -PartitionNumber $temp.PartitionNumber -AccessPath "$($temp.Letter):\" -ErrorAction SilentlyContinue
                } catch {}
            }
            foreach ($letter in $hiddenDriveLetters) {
                try {
                    Show-DriveInExplorer -DriveLetter $letter
                } catch {}
            }

            $totalTime = (Get-Date) - $startTime
            Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
            Write-Host "    ║                   CLONADO CANCELADO                             ║" -ForegroundColor Yellow
            Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Yellow
            Write-Host "    ║  Progreso:        $("{0,-45}" -f "$([math]::Round($globalCopiedGB, 1)) GB de $totalUsedGB GB")║" -ForegroundColor White
            Write-Host "    ║  Tiempo:          $("{0,-45}" -f "$([math]::Floor($totalTime.TotalMinutes))m $([math]::Round($totalTime.Seconds))s")║" -ForegroundColor White
            Write-Host "    ║                                                                 ║" -ForegroundColor Yellow
            Write-Host "    ║  [!] El disco DESTINO quedo INCOMPLETO                          ║" -ForegroundColor Red
            Write-Host "    ║  [!] Formatealo antes de usarlo o reinicia el clonado           ║" -ForegroundColor Red
            Write-Host "    ║                                                                 ║" -ForegroundColor Yellow
            Write-Host "    ║  El disco ORIGEN no fue modificado (siempre a salvo)            ║" -ForegroundColor Green
            Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
            return $false
        }

        # Actualizar GB copiados globalmente
        $globalCopiedGB += $usedGB

        # Esperar a que termine y limpiar línea
        $robocopyProcess.WaitForExit()
        Write-Host ""

        if ($robocopyProcess.ExitCode -lt 8) {
            Write-Host "        [OK] Particion $srcLetter`: copiada correctamente" -ForegroundColor Green
        } else {
            Write-Host "        [!] Algunos archivos no se copiaron (codigo: $($robocopyProcess.ExitCode))" -ForegroundColor Red
        }
        Write-Host ""
    }

    # PASO 4: Verificación
    Write-Host "  [4/6] Verificando integridad..." -ForegroundColor Cyan
    Write-Host ""

    $verificacionOK = $true
    $dstPartitions = Get-Partition -DiskNumber $DestDisk -ErrorAction SilentlyContinue |
                     Where-Object { $_.DriveLetter } | Sort-Object PartitionNumber

    $totalSrcFiles = 0
    $totalDstFiles = 0
    $totalSrcSize = 0
    $totalDstSize = 0

    for ($i = 0; $i -lt [Math]::Min($srcPartitions.Count, $dstPartitions.Count); $i++) {
        $srcLetter = $srcPartitions[$i].DriveLetter
        $dstLetter = $dstPartitions[$i].DriveLetter

        Write-Host "    Verificando $srcLetter`: vs $dstLetter`:..." -ForegroundColor Gray

        # Contar archivos y tamaño en origen
        $srcStats = Get-ChildItem -Path "$srcLetter`:\" -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum
        $srcFiles = $srcStats.Count
        $srcSize = $srcStats.Sum

        # Contar archivos y tamaño en destino
        $dstStats = Get-ChildItem -Path "$dstLetter`:\" -Recurse -File -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum
        $dstFiles = $dstStats.Count
        $dstSize = $dstStats.Sum

        $totalSrcFiles += $srcFiles
        $totalDstFiles += $dstFiles
        $totalSrcSize += $srcSize
        $totalDstSize += $dstSize

        # Calcular porcentaje de integridad
        $pctFiles = if ($srcFiles -gt 0) { [math]::Round(($dstFiles / $srcFiles) * 100, 1) } else { 100 }
        $pctSize = if ($srcSize -gt 0) { [math]::Round(($dstSize / $srcSize) * 100, 1) } else { 100 }

        if ($pctFiles -ge 99 -and $pctSize -ge 99) {
            Write-Host "      [OK] $dstFiles/$srcFiles archivos ($pctSize% datos)" -ForegroundColor Green
        } elseif ($pctFiles -ge 95) {
            Write-Host "      [~] $dstFiles/$srcFiles archivos ($pctSize% datos) - Casi completo" -ForegroundColor Yellow
        } else {
            Write-Host "      [!] $dstFiles/$srcFiles archivos ($pctSize% datos) - INCOMPLETO" -ForegroundColor Red
            $verificacionOK = $false
        }
    }
    Write-Host ""

    # PASO 5: Resumen final
    $duration = (Get-Date) - $startTime
    $durationStr = "{0:hh\:mm\:ss}" -f $duration
    $avgSpeedMBs = if ($duration.TotalSeconds -gt 0) {
        [math]::Round(($totalDstSize / 1MB) / $duration.TotalSeconds, 1)
    } else { 0 }

    Write-Host ""
    if ($verificacionOK) {
        Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "  ║           ✓ CLONACION COMPLETADA CON EXITO ✓                  ║" -ForegroundColor Green
        Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    } else {
        Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "  ║        ! CLONACION COMPLETADA CON ADVERTENCIAS !              ║" -ForegroundColor Yellow
        Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  ESTADISTICAS DE LA CLONACION                                   │" -ForegroundColor Cyan
    Write-Host "  ├─────────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
    Write-Host "  │  Duracion total:     $($durationStr.PadRight(42))│" -ForegroundColor White
    Write-Host "  │  Datos copiados:     $("$([math]::Round($totalDstSize/1GB, 2)) GB".PadRight(42))│" -ForegroundColor White
    Write-Host "  │  Archivos copiados:  $("$totalDstFiles archivos".PadRight(42))│" -ForegroundColor White
    Write-Host "  │  Velocidad media:    $("$avgSpeedMBs MB/s".PadRight(42))│" -ForegroundColor White
    Write-Host "  │  Integridad:         $(if($verificacionOK){"OK - Verificado".PadRight(42)}else{"REVISAR - Algunos archivos faltantes".PadRight(42)})│" -ForegroundColor $(if($verificacionOK){"Green"}else{"Yellow"})
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Particiones clonadas:" -ForegroundColor White
    foreach ($p in $srcPartitions) {
        Write-Host "    ✓ $($p.DriveLetter):" -ForegroundColor Gray
    }
    Write-Host ""

    # Limpiar: quitar letras temporales que asignamos
    if ($tempLettersAssigned.Count -gt 0) {
        Write-Host "  [5/6] Limpiando letras temporales..." -ForegroundColor Gray
        foreach ($tmp in $tempLettersAssigned) {
            try {
                # Mostrar en Explorer antes de quitar
                Show-DriveInExplorer -DriveLetter $tmp.Letter
                Remove-PartitionAccessPath -DiskNumber $tmp.DiskNumber -PartitionNumber $tmp.PartitionNumber -AccessPath "$($tmp.Letter):\" -ErrorAction SilentlyContinue
                Write-Host "        Quitada letra temporal $($tmp.Letter):" -ForegroundColor Gray
            } catch {
                # Ignorar errores al quitar letras
            }
        }
        Write-Host ""
    }

    # PASO 6: Reparar bootloader para que el disco clonado arranque
    Write-Host "  [6/6] Reparando bootloader del disco clonado..." -ForegroundColor Cyan
    $bootRepaired = Repair-BootLoader -DiskNumber $DestDisk
    if ($bootRepaired) {
        Write-Host "  [OK] Disco listo para arrancar" -ForegroundColor Green
    } else {
        Write-Host "  [!] Bootloader no reparado - puede requerir reparacion manual" -ForegroundColor Yellow
        Write-Host "      Usa: bcdboot X:\Windows /s Y: /f ALL" -ForegroundColor Gray
    }
    Write-Host ""

    # Restaurar: mostrar unidades en Explorer y reactivar popups
    Write-Host "  Restaurando entorno..." -ForegroundColor Gray
    foreach ($letter in $hiddenDriveLetters) {
        Show-DriveInExplorer -DriveLetter $letter
    }
    Enable-FormatPopups
    Write-Host ""
    
    # Cerrar LOG y mostrar ubicacion
    Stop-CloneLog -Success $verificacionOK -Duration $durationStr
    Write-CloneLog "Clonacion finalizada - $([math]::Round($totalDstSize/1GB, 2)) GB copiados en $durationStr"
    Write-Host "  ┌─────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  LOG GUARDADO: $($script:CurrentLogFile.PadRight(48))│" -ForegroundColor DarkGray
    Write-Host "  └─────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host ""

    # Refrescar Explorer para que aparezca el disco clonado
    Refresh-Explorer

    return $true
}

# ===============================================================================
# RESTAURAR DESDE IMAGEN
# ===============================================================================

function Restore-DiskImage {
    param(
        [string]$ImagePath,
        [int]$DestDisk
    )

    Write-Host ""
    Write-Host "  [RESTAURAR IMAGEN]" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────────" -ForegroundColor DarkGray

    if (-not (Test-Path $ImagePath)) {
        Write-Host "  [ERROR] Imagen no encontrada: $ImagePath" -ForegroundColor Red
        return $false
    }

    $ext = [System.IO.Path]::GetExtension($ImagePath).ToUpper()

    Write-Host "  Imagen:   $ImagePath" -ForegroundColor White
    Write-Host "  Formato:  $ext" -ForegroundColor White
    Write-Host "  Destino:  Disco $DestDisk" -ForegroundColor White
    Write-Host ""

    Write-Host "  [ADVERTENCIA] Esta operacion BORRARA TODOS LOS DATOS del disco destino!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  ¿Continuar? [S/N]: " -NoNewline -ForegroundColor Yellow
    $continuar = Read-Host
    if ($continuar -notmatch "^[Ss]$") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }
    Write-Host ""
    Write-Host "  Escribe 'RESTAURAR' para confirmar: " -NoNewline -ForegroundColor Yellow
    $confirm = Read-Host

    if ($confirm -ne "RESTAURAR") {
        Write-Host "  Operacion cancelada." -ForegroundColor Yellow
        return $false
    }

    if ($ext -eq ".VHDX" -or $ext -eq ".VHD") {
        # Montar VHD y copiar contenido
        Write-Host "  Montando imagen VHD..." -ForegroundColor Yellow

        try {
            Mount-VHD -Path $ImagePath -ReadOnly
            $vhd = Get-VHD -Path $ImagePath

            # Copiar particiones...
            Write-Host "  Copiando datos desde imagen..." -ForegroundColor Gray

            Dismount-VHD -Path $ImagePath

        } catch {
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }

    } elseif ($ext -eq ".WIM") {
        # Usar DISM para restaurar
        Write-Host "  Aplicando imagen WIM con DISM..." -ForegroundColor Yellow

        $dstPartitions = Get-Partition -DiskNumber $DestDisk | Where-Object { $_.DriveLetter }

        if ($dstPartitions.Count -eq 0) {
            Write-Host "  [ERROR] El disco destino no tiene particiones con letra asignada." -ForegroundColor Red
            return $false
        }

        $dstLetter = $dstPartitions[0].DriveLetter

        $dismArgs = "/Apply-Image /ImageFile:`"$ImagePath`" /Index:1 /ApplyDir:$dstLetter`:\"

        try {
            $process = Start-Process -FilePath "dism.exe" -ArgumentList $dismArgs -NoNewWindow -Wait -PassThru
            if ($process.ExitCode -eq 0) {
                Write-Host "  [OK] Imagen restaurada!" -ForegroundColor Green
            } else {
                Write-Host "  [ERROR] DISM retorno codigo: $($process.ExitCode)" -ForegroundColor Red
            }
        } catch {
            Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
    }

    return $true
}

# ===============================================================================
# MENU PRINCIPAL
function Show-Menu {
    # Splash de Nala al inicio (solo la primera vez)
    Show-NalaSplash

    # Fondo azul oscuro
    $Host.UI.RawUI.BackgroundColor = 'DarkBlue'
    $Host.UI.RawUI.ForegroundColor = 'White'
    Clear-Host

    if (-not (Test-AdminRequired)) {
        Read-Host "  ENTER para salir"
        return
    }

    while ($true) {
        # Menu principal interactivo con flechas
        # DISEÑO 6 COLUMNAS: | ► | [Key] | Label | Description | RECOMENDADO | ◄ |
        $menuOptions = @(
            @{ Key = "0"; Label = "Ver discos conectados"; Description = "Lista todos los discos" }
            @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
            @{ Key = "1"; Label = "CLONAR DISCO"; Description = "WimLib, 100-200+ MB/s"; Recommended = $true }
            @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
            @{ Key = "3"; Label = "Borrar disco"; Description = "Rapido, GPT + NTFS" }
            @{ Key = "4"; Label = "Borrado avanzado"; Description = "Seguro, elegir formato" }
            @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
            @{ Key = "5"; Label = "Opciones avanzadas"; Description = "FIERY, imagenes, rescate" }
            @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
            @{ Key = "R"; Label = "Refrescar Explorer"; Description = "Detectar discos nuevos" }
            @{ Key = "6"; Label = "Ver logs"; Description = "Abre carpeta de logs" }
            @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
            @{ Key = "X"; Label = "Salir"; Description = "" }
        )

        $opcion = Show-InteractiveMenu -Title "MENU PRINCIPAL" -Options $menuOptions

        switch ($opcion) {
            "0" {
                # Ver discos conectados
                Clear-Host
                Write-Host ""
                Write-Host "    DISCOS CONECTADOS" -ForegroundColor Cyan
                Write-Host "    ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
                Write-Host ""
                Get-DiskList | Out-Null
                Write-Host ""
                Write-Host "    Pulsa cualquier tecla para volver..." -ForegroundColor DarkGray
                Read-TeclaSafe | Out-Null
            }
            "1" {
                # Clonar RAPIDO con WIMLIB - Seleccion interactiva
                $srcDisk = Select-DiskInteractive -Title "CLONAR RAPIDO - DISCO ORIGEN" -Prompt "Selecciona el disco que quieres COPIAR"
                if (-not $srcDisk) { continue }

                $dstDisk = Select-DiskInteractive -Title "CLONAR RAPIDO - DISCO DESTINO" -Prompt "Selecciona el disco DESTINO (se borrara)" -ExcludeWindows
                if (-not $dstDisk) { continue }

                if ($srcDisk.DiskNumber -eq $dstDisk.DiskNumber) {
                    Write-Host ""
                    Write-Host "  [ERROR] Origen y destino no pueden ser el mismo disco" -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    continue
                }

                $null = Copy-DiskFast -SourceDisk $srcDisk.DiskNumber -DestDisk $dstDisk.DiskNumber
                Write-Host ""
                Write-Host "    Pulsa cualquier tecla para volver..." -ForegroundColor DarkGray
                Read-TeclaSafe | Out-Null
            }
            "5" {
                # Submenu opciones avanzadas - INTERACTIVO
                $volverMenu = $false
                while (-not $volverMenu) {
                    # Opciones del submenu avanzadas (6 columnas)
                    $advMenuOptions = @(
                        @{ Key = "1"; Label = "Crear imagen de disco"; Description = "VHDX/WIM" }
                        @{ Key = "2"; Label = "Restaurar imagen a disco"; Description = "Desde imagen" }
                        @{ Key = "3"; Label = "Ver imagenes guardadas"; Description = "Carpeta backups" }
                        @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
                        @{ Key = "H"; Label = "Health Check"; Description = "SMART, errores" }
                        @{ Key = "R"; Label = "Rescatar disco oculto"; Description = "Invisible/offline" }
                        @{ Key = "O"; Label = "Ocultar disco Explorer"; Description = "NoDrives policy" }
                        @{ Key = "L"; Label = "Limpiar letras huerfanas"; Description = "U:, V:, W:..." }
                        @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
                        @{ Key = "B"; Label = "Clonado COMPLETO"; Description = "EFI+MSR+Recovery"; Recommended = $true }
                        @{ Key = "Q"; Label = "Backup RAPIDO"; Description = "NO booteable" }
                        @{ Key = "F"; Label = "Modo FIERY"; Description = "Controladores RIP" }
                        @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
                        @{ Key = "D"; Label = "Administracion de Discos"; Description = "Windows" }
                        @{ Key = "E"; Label = "Liberador de Espacio"; Description = "Windows" }
                        @{ Key = "-"; Label = ""; Description = ""; Disabled = $true }
                        @{ Key = "V"; Label = "Volver"; Description = "Menu anterior" }
                        @{ Key = "X"; Label = "Salir"; Description = "" }
                    )

                    $subOpcion = Show-InteractiveMenu -Title "OPCIONES AVANZADAS" -Options $advMenuOptions

                    switch ($subOpcion.ToUpper()) {
                        "1" {
                            # Crear imagen de disco
                            $src = Select-DiskInteractive -Title "CREAR IMAGEN DE DISCO" -Prompt "Selecciona el disco a convertir en imagen"
                            if ($src) {
                                # Seleccionar formato con menu interactivo
                                $formatOptions = @(
                                    @{ Key = "1"; Label = "VHDX"; Description = "Disco virtual (montar)"; Recommended = $true }
                                    @{ Key = "2"; Label = "WIM"; Description = "Imagen comprimida" }
                                    @{ Key = "V"; Label = "Volver"; Description = "Menu anterior" }
                                )
                                $formatChoice = Show-InteractiveMenu -Title "FORMATO DE IMAGEN" -Subtitle "Disco $($src.DiskNumber) - $($src.SizeGB) GB" -Options $formatOptions

                                if ($formatChoice -ne "V") {
                                    $format = if ($formatChoice -eq "2") { "WIM" } else { "VHDX" }
                                    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
                                    $filename = "Disco$($src.DiskNumber)_$timestamp.$($format.ToLower())"
                                    $outputPath = Join-Path $script:CONFIG.BackupPath $filename

                                    New-DiskImage -DiskNumber $src.DiskNumber -OutputPath $outputPath -Format $format
                                    Write-Host ""
                                    Read-Host "  ENTER para continuar"
                                }
                            }
                        }
                        "2" {
                            # Restaurar imagen
                            Clear-Host
                            Show-Logo -Subtitulo "RESTAURAR IMAGEN A DISCO"
                            $backupDir = $script:CONFIG.BackupPath
                            if (Test-Path $backupDir) {
                                $images = Get-ChildItem $backupDir -Include "*.vhdx","*.wim","*.vhd" -Recurse -ErrorAction SilentlyContinue
                                if ($images -and $images.Count -gt 0) {
                                    Write-Host "  Imagenes disponibles:" -ForegroundColor Cyan
                                    Write-Host ""
                                    $i = 1
                                    foreach ($img in $images) {
                                        $sizeGB = [math]::Round($img.Length / 1GB, 2)
                                        $fecha = $img.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                                        Write-Host "    [$i] $($img.Name) ($sizeGB GB) - $fecha" -ForegroundColor White
                                        $i++
                                    }
                                    Write-Host ""
                                    Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                                    Write-Host ""
                                    Write-Host "  Selecciona imagen (numero): " -NoNewline -ForegroundColor Yellow
                                    $imgIdx = Read-Host
                                    if ($imgIdx -match "^[XxZz]$") { continue }

                                    if ($imgIdx -match "^\d+$" -and [int]$imgIdx -ge 1 -and [int]$imgIdx -le $images.Count) {
                                        $selectedImg = $images[[int]$imgIdx - 1]
                                        Write-Host ""
                                        $disks = Get-DiskList
                                        Write-Host ""
                                        Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                                        Write-Host ""
                                        Write-Host "  Selecciona disco DESTINO (numero): " -NoNewline -ForegroundColor Yellow
                                        $dstIdx = Read-Host
                                        if ($dstIdx -match "^[XxZz]$") { continue }
                                        
                                        if ($dstIdx -match "^\d+$") {
                                            $dst = $disks | Where-Object { $_.Index -eq [int]$dstIdx }
                                            if ($dst) {
                                                Restore-DiskImage -ImagePath $selectedImg.FullName -DestDisk $dst.DiskNumber
                                            }
                                        } else {
                                            Write-Host "  [ERROR] Introduce un numero valido." -ForegroundColor Red
                                        }
                                    } else {
                                        Write-Host "  Seleccion invalida." -ForegroundColor Yellow
                                    }
                                } else {
                                    Write-Host "  No hay imagenes guardadas en: $backupDir" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "  Directorio de backups no existe: $backupDir" -ForegroundColor Yellow
                            }
                            Write-Host ""
                Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                Write-Host ""
                Read-Host "  Opcion"
                        }
                        "3" {
                            # Ver imagenes
                            Clear-Host
                            Show-Logo -Subtitulo "IMAGENES GUARDADAS"
                            $backupDir = $script:CONFIG.BackupPath
                            Write-Host "  Directorio: $backupDir" -ForegroundColor Cyan
                            Write-Host ""
                            if (Test-Path $backupDir) {
                                $images = Get-ChildItem $backupDir -Include "*.vhdx","*.wim","*.vhd" -Recurse -ErrorAction SilentlyContinue
                                if ($images -and $images.Count -gt 0) {
                                    foreach ($img in $images) {
                                        $sizeGB = [math]::Round($img.Length / 1GB, 2)
                                        $fecha = $img.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                                        Write-Host "    $($img.Name) - $sizeGB GB - $fecha" -ForegroundColor White
                                    }
                                    Write-Host ""
                                    Write-Host "  Total: $($images.Count) imagen(es)" -ForegroundColor Gray
                                } else {
                                    Write-Host "  No hay imagenes guardadas." -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "  Directorio no existe." -ForegroundColor Yellow
                            }
                            Write-Host ""
                Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                Write-Host ""
                Read-Host "  Opcion"
                        }
                        "H" {
                            # Health Check
                            $selectedDisk = Select-DiskInteractive -Title "HEALTH CHECK" -Prompt "Analiza SMART, compresion, desgaste SSD..."
                            if ($selectedDisk) {
                                Show-DiskHealthCheck -DiskNumber $selectedDisk.DiskNumber
                                Write-Host ""
                                Read-Host "  ENTER para continuar"
                            }
                        }
                        "R" {
                            # Rescatar disco
                            Clear-Host
                            Show-Logo -Subtitulo "RESCATAR DISCO INVISIBLE"
                            Write-Host ""
                            Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                            Write-Host "    ║                 RESCATAR DISCO INVISIBLE                        ║" -ForegroundColor Cyan
                            Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                            Write-Host "    ║                                                                 ║" -ForegroundColor Cyan
                            Write-Host "    ║  Busca discos que Windows no muestra en el Explorador:          ║" -ForegroundColor White
                            Write-Host "    ║    - Discos sin letra asignada                                  ║" -ForegroundColor Gray
                            Write-Host "    ║    - Discos offline o en modo RAW                               ║" -ForegroundColor Gray
                            Write-Host "    ║    - Discos ocultos via registro                                ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Cyan
                            Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                            Write-Host ""
                            Show-HiddenDisks
                            Write-Host ""
                            Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                            Write-Host ""
                            Read-Host "    Opcion"
                        }
                        "O" {
                            # Ocultar disco
                            $selectedDisk = Select-DiskInteractive -Title "OCULTAR DISCO" -Prompt "Oculta el disco del Explorador (sigue funcionando)" -ExcludeWindows
                            if ($selectedDisk) {
                                Clear-Host
                                Show-Logo -Subtitulo "OCULTAR DISCO"
                                foreach ($vol in $selectedDisk.Volumenes) {
                                    if ($vol.Letra) {
                                        Hide-DriveFromExplorer -DriveLetter ($vol.Letra.TrimEnd(':'))
                                        Write-Host "  [OK] Ocultada $($vol.Letra)" -ForegroundColor Green
                                    }
                                }
                                Write-Host ""
                                Write-Host "  [OK] Disco ocultado. Actualiza Explorer (F5)." -ForegroundColor Green
                                Write-Host ""
                                Read-Host "  ENTER para continuar"
                            }
                        }
                        "L" {
                            # Limpiar letras huérfanas
                            Clear-Host
                            Show-Logo -Subtitulo "LIMPIAR LETRAS HUERFANAS"
                            Write-Host ""
                            Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
                            Write-Host "    ║               LIMPIAR LETRAS HUERFANAS                          ║" -ForegroundColor Cyan
                            Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
                            Write-Host "    ║                                                                 ║" -ForegroundColor Cyan
                            Write-Host "    ║  Busca y elimina letras de unidad asignadas a:                  ║" -ForegroundColor White
                            Write-Host "    ║    - Particiones de sistema (Recovery, Reserved, EFI)           ║" -ForegroundColor Gray
                            Write-Host "    ║    - Particiones pequenas (<1GB)                                ║" -ForegroundColor Gray
                            Write-Host "    ║    - Letras temporales sin usar (U:, V:, W:, X:, Y:, Z:)        ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Cyan
                            Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
                            Write-Host ""
                            Write-Host "    Buscando particiones ocultas con letras asignadas..." -ForegroundColor Gray
                            Write-Host ""
                            $huerfanas = @()
                            $allDisks = Get-Disk | Where-Object { $_.OperationalStatus -eq "Online" }
                            foreach ($disk in $allDisks) {
                                $particiones = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
                                foreach ($part in $particiones) {
                                    if ($part.DriveLetter) {
                                        $vol = Get-Volume -DriveLetter $part.DriveLetter -ErrorAction SilentlyContinue
                                        $esHuerfana = $false
                                        $razon = ""
                                        if ($part.Type -in @("System", "Recovery", "Reserved")) {
                                            $esHuerfana = $true; $razon = "Particion de sistema"
                                        } elseif ($part.Size -lt 1GB) {
                                            $esHuerfana = $true; $razon = "Particion pequena"
                                        } elseif ($part.DriveLetter -in @('U','V','W','X','Y','Z')) {
                                            $nombre = if ($vol.FileSystemLabel) { $vol.FileSystemLabel } else { "Sin nombre" }
                                            if ($nombre -eq "Sin nombre" -or $nombre -eq "SYSTEM_DRV") {
                                                $esHuerfana = $true; $razon = "Letra temporal"
                                            }
                                        }
                                        if ($esHuerfana) {
                                            $huerfanas += @{ DiskNumber = $disk.Number; PartitionNumber = $part.PartitionNumber; DriveLetter = $part.DriveLetter; Razon = $razon }
                                        }
                                    }
                                }
                            }
                            if ($huerfanas.Count -eq 0) {
                                Write-Host "    [OK] No hay letras huerfanas." -ForegroundColor Green
                            } else {
                                Write-Host "    Encontradas $($huerfanas.Count) letra(s) huerfana(s):" -ForegroundColor Yellow
                                Write-Host ""
                                foreach ($h in $huerfanas) {
                                    Write-Host "      $($h.DriveLetter): - $($h.Razon)" -ForegroundColor White
                                }
                                Write-Host ""
                                Write-Host "    Quitar TODAS? [S/N]: " -NoNewline -ForegroundColor Yellow
                                if ((Read-Host) -match "^[Ss]") {
                                    Write-Host ""
                                    foreach ($h in $huerfanas) {
                                        try {
                                            Remove-PartitionAccessPath -DiskNumber $h.DiskNumber -PartitionNumber $h.PartitionNumber -AccessPath "$($h.DriveLetter):\" -ErrorAction Stop
                                            Write-Host "      [OK] Quitada $($h.DriveLetter):" -ForegroundColor Green
                                        } catch {
                                            Write-Host "      [!] Error: $($h.DriveLetter):" -ForegroundColor Yellow
                                        }
                                    }
                                }
                            }
                            Write-Host ""
                            Write-Host "    [V] Volver   [X] Salir" -ForegroundColor DarkGray
                            Write-Host ""
                            Read-Host "    Opcion"
                        }
                                                "D" {
                            # Abrir Administracion de Discos de Windows
                            Start-Process "diskmgmt.msc"
                            Write-Host ""
                            Write-Host "  Abriendo Administracion de Discos de Windows..." -ForegroundColor Cyan
                            Start-Sleep -Seconds 1
                        }
                        "E" {
                            # Abrir Liberador de Espacio de Windows
                            Start-Process "cleanmgr.exe"
                            Write-Host ""
                            Write-Host "  Abriendo Liberador de Espacio de Windows..." -ForegroundColor Cyan
                            Start-Sleep -Seconds 1
                        }
                        "B" {
                            # Clonado COMPLETO - Todas las particiones (EFI, MSR, Recovery, Windows)
                            $src = Select-DiskInteractive -Title "CLONADO COMPLETO - ORIGEN" -Prompt "Clona TODAS las particiones (EFI, MSR, Recovery, Windows)"
                            if (-not $src) { continue }

                            $dst = Select-DiskInteractive -Title "CLONADO COMPLETO - DESTINO" -Prompt "Se borrara para recibir el clon" -ExcludeWindows
                            if (-not $dst) { continue }

                            if ($src.DiskNumber -ne $dst.DiskNumber) {
                                Copy-DiskComplete -SourceDisk $src.DiskNumber -DestDisk $dst.DiskNumber
                                Write-Host ""
                                Read-Host "  ENTER para continuar"
                            }
                        }
                        "Q" {
                            # Backup RAPIDO - Sin WinSxS (NO booteable, solo datos)
                            $src = Select-DiskInteractive -Title "BACKUP RAPIDO - ORIGEN" -Prompt "Sin WinSxS (NO booteable, solo DATOS)"
                            if (-not $src) { continue }

                            $dst = Select-DiskInteractive -Title "BACKUP RAPIDO - DESTINO" -Prompt "Se borrara para recibir el backup" -ExcludeWindows
                            if (-not $dst) { continue }

                            if ($src.DiskNumber -ne $dst.DiskNumber) {
                                Clear-Host
                                Show-Logo -Subtitulo "BACKUP RAPIDO"
                                Write-Host ""
                                Write-Host "  ORIGEN:  Disco $($src.DiskNumber) - $($src.HWName) ($($src.SizeGB) GB)" -ForegroundColor White
                                Write-Host "  DESTINO: Disco $($dst.DiskNumber) - $($dst.HWName) ($($dst.SizeGB) GB)" -ForegroundColor White
                                Write-Host ""
                                Write-Host "  [!] BACKUP RAPIDO: Excluye WinSxS (NO booteable)" -ForegroundColor Yellow
                                Write-Host ""
                                Write-Host "  Escribe BACKUP para continuar: " -NoNewline -ForegroundColor Red
                                $confirm = Read-Host
                                if ($confirm -eq "BACKUP") {
                                    Copy-DiskToDisk -SourceDisk $src.DiskNumber -DestDisk $dst.DiskNumber -ExcludeWinSxS
                                } else {
                                    Write-Host "  Operacion cancelada." -ForegroundColor Yellow
                                }
                                Write-Host ""
                                Read-Host "  ENTER para continuar"
                            }
                        }
                        "F" {
                            # Modo FIERY - Controladores RIP de impresion
                            Clear-Host

                            # Logo FIERY estilo CLONADISCOS (Red #EF3344, 4 espacios)
                            Write-Host ""
                            Write-Host "    ███████╗██╗███████╗██████╗ ██╗   ██╗" -ForegroundColor Red
                            Write-Host "    ██╔════╝██║██╔════╝██╔══██╗╚██╗ ██╔╝" -ForegroundColor Red
                            Write-Host "    █████╗  ██║█████╗  ██████╔╝ ╚████╔╝ " -ForegroundColor Red
                            Write-Host "    ██╔══╝  ██║██╔══╝  ██╔══██╗  ╚██╔╝  " -ForegroundColor Red
                            Write-Host "    ██║     ██║███████╗██║  ██║   ██║   " -ForegroundColor Red
                            Write-Host "    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   " -ForegroundColor Red
                            Write-Host ""
                            Write-Host "    CLONE MODE - Controladores RIP de impresion" -ForegroundColor DarkGray
                            Write-Host ""

                            # Advertencias especificas para Fiery
                            Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                            Write-Host "    ║                    ADVERTENCIAS FIERY                          ║" -ForegroundColor Red
                            Write-Host "    ╠═════════════════════════════════════════════════════════════════╣" -ForegroundColor Red
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║  " -ForegroundColor Red -NoNewline
                            Write-Host "[!] ANTES de clonar un Fiery, asegurate de:" -ForegroundColor Red -NoNewline
                            Write-Host "                   ║" -ForegroundColor Red
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║      1. PARAR la cola de impresion                             ║" -ForegroundColor White
                            Write-Host "    ║         (Fiery Command WorkStation > Server > Stop Printing)   ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║      2. EXPORTAR los perfiles ICC personalizados               ║" -ForegroundColor White
                            Write-Host "    ║         (Device Center > Resources > Profiles > Export)        ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║      3. EXPORTAR los presets de trabajo                        ║" -ForegroundColor White
                            Write-Host "    ║         (Server > Job Presets > Export All)                    ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║      4. ANOTAR la configuracion de red del Fiery               ║" -ForegroundColor White
                            Write-Host "    ║         (IP, mascara, gateway, DNS)                            ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ║      5. APAGAR el Fiery correctamente antes de desconectar     ║" -ForegroundColor White
                            Write-Host "    ║         (Fiery > Shut Down, esperar a que apague)              ║" -ForegroundColor Gray
                            Write-Host "    ║                                                                 ║" -ForegroundColor Red
                            Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                            Write-Host ""

                            Write-Host "    NOTA: Los Fiery suelen tener Windows Embedded con disco SSD de"   -ForegroundColor Cyan
                            Write-Host "          60-120GB. El clon incluira la licencia del Fiery."          -ForegroundColor Cyan
                            Write-Host ""
                            Write-Host "    El clon NO incluye:" -ForegroundColor Yellow
                            Write-Host "      - Calibraciones de color (hay que recalibrar en destino)" -ForegroundColor Gray
                            Write-Host "      - Licencias de software adicional (Impose, Compose, etc.)" -ForegroundColor Gray
                            Write-Host ""

                            Write-Host "    Continuar con el clonado? [S/N]: " -NoNewline -ForegroundColor Yellow
                            $continuar = Read-Host

                            if ($continuar -match "^[Ss]$") {
                                $src = Select-DiskInteractive -Title "FIERY - DISCO ORIGEN" -Prompt "Selecciona el disco del Fiery a clonar"
                                if (-not $src) { continue }

                                $dst = Select-DiskInteractive -Title "FIERY - DISCO DESTINO" -Prompt "Disco de respaldo/clon" -ExcludeWindows
                                if (-not $dst) { continue }

                                if ($src.DiskNumber -ne $dst.DiskNumber) {
                                    $puedesClonar = $true

                                    if ($src.TieneBitLocker) {
                                        Write-Host ""
                                        Write-Host "  [ERROR] El disco Fiery tiene BitLocker activo!" -ForegroundColor Red
                                        Write-Host "  Los Fiery normalmente no usan BitLocker. Verifica." -ForegroundColor Yellow
                                        $puedesClonar = $false
                                    }

                                    if ($puedesClonar) {
                                        Clear-Host
                                        Write-Host ""
                                        Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                                        Write-Host "    ║                  CLONANDO FIERY                                 ║" -ForegroundColor Red
                                        Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                                        Write-Host ""
                                        # Usar WIMLIB para Fiery (mas compatible que RAW)
                                        $null = Copy-DiskFast -SourceDisk $src.DiskNumber -DestDisk $dst.DiskNumber
                                        Write-Host ""
                                        Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                                        Write-Host "  ║  POST-CLONADO FIERY:                                          ║" -ForegroundColor Green
                                        Write-Host "  ║                                                               ║" -ForegroundColor Green
                                        Write-Host "  ║  1. Instala el disco clonado en el Fiery nuevo               ║" -ForegroundColor White
                                        Write-Host "  ║  2. Arranca y configura la IP de red                         ║" -ForegroundColor White
                                        Write-Host "  ║  3. Importa los perfiles ICC exportados                      ║" -ForegroundColor White
                                        Write-Host "  ║  4. Recalibra el color (Device Center > Calibration)         ║" -ForegroundColor White
                                        Write-Host "  ║  5. Verifica licencias en Configure > Software Installs      ║" -ForegroundColor White
                                        Write-Host "  ║                                                               ║" -ForegroundColor Green
                                        Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                                    }
                                    Write-Host ""
                                    Read-Host "  ENTER para continuar"
                                }
                            }
                        }
                        "X" { return }
                        "V" { $volverMenu = $true }
                        default { Write-Host "  Opcion no valida." -ForegroundColor Yellow; Start-Sleep -Seconds 1 }
                    }
                }
            }
            "3" {
                # Borrar disco SIMPLE - Un click, listo para usar
                $selectedDisk = Select-DiskInteractive -Title "BORRAR DISCO" -Prompt "Borra el disco y lo deja listo (GPT + NTFS)" -ExcludeWindows

                if ($selectedDisk) {
                    Clear-Host
                    Show-Logo -Subtitulo "BORRAR DISCO"
                    Write-Host ""
                    Write-Host "  Disco seleccionado: $($selectedDisk.HWName) ($($selectedDisk.SizeGB) GB)" -ForegroundColor White

                    # DOBLE CONFIRMACION
                    $actionDesc = "BORRAR disco $($selectedDisk.DiskNumber) - $($selectedDisk.HWName)"
                    $targetDesc = "Disco $($selectedDisk.DiskNumber) - $($selectedDisk.HWName) ($($selectedDisk.SizeGB) GB)"

                    if (Confirm-CriticalAction -Action $actionDesc -Keyword "BORRAR" -TargetName $targetDesc -DangerLevel "danger") {
                            Write-Host ""
                            Write-Host "  [1/3] Borrando disco..." -ForegroundColor Yellow
                            try {
                                Clear-Disk -Number $selectedDisk.DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
                                Write-Host "        OK" -ForegroundColor Green

                                Write-Host "  [2/3] Inicializando (GPT)..." -ForegroundColor Yellow
                                Initialize-Disk -Number $selectedDisk.DiskNumber -PartitionStyle GPT -ErrorAction Stop
                                Write-Host "        OK" -ForegroundColor Green

                                Write-Host "  [3/3] Formateando (NTFS)..." -ForegroundColor Yellow
                                $newPart = New-Partition -DiskNumber $selectedDisk.DiskNumber -UseMaximumSize -AssignDriveLetter -ErrorAction Stop
                                Format-Volume -DriveLetter $newPart.DriveLetter -FileSystem NTFS -NewFileSystemLabel "USB" -Confirm:$false -ErrorAction Stop | Out-Null
                                Write-Host "        OK" -ForegroundColor Green

                                Write-Host ""
                                Write-Host "  ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                                Write-Host "  ║  DISCO LISTO!  Unidad: $($newPart.DriveLetter):   Formato: NTFS                  ║" -ForegroundColor Green
                                Write-Host "  ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                            } catch {
                                Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                            }
                    }
                    Write-Host ""
                    Read-Host "  ENTER para continuar"
                }
            }
            "4" {
                # Borrar/Limpiar disco AVANZADO
                $selectedDisk = Select-DiskInteractive -Title "BORRADO AVANZADO" -Prompt "ATENCION: Borra TODOS los datos de forma IRREVERSIBLE"

                if ($selectedDisk) {
                    # Advertencia extra si es disco de Windows
                    if ($selectedDisk.TieneWindows) {
                        Clear-Host
                        Show-Logo -Subtitulo "BORRADO AVANZADO"
                        Write-Host ""
                        Write-Host "    ╔═════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                        Write-Host "    ║  [!] ESTE DISCO CONTIENE WINDOWS !!                             ║" -ForegroundColor Red
                        Write-Host "    ║  Si lo borras, tu PC no arrancara.                              ║" -ForegroundColor Red
                        Write-Host "    ╚═════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                    }

                    # Seleccionar tipo de borrado con menu interactivo
                    $borradoOptions = @(
                        @{ Key = "1"; Label = "Borrado RAPIDO"; Description = "Solo borra particiones"; Recommended = $true }
                        @{ Key = "2"; Label = "Borrado SEGURO"; Description = "Sobrescribe con ceros" }
                        @{ Key = "V"; Label = "Volver"; Description = "Menu anterior" }
                    )
                    $tipoB = Show-InteractiveMenu -Title "TIPO DE BORRADO" -Subtitle "$($selectedDisk.HWName) ($($selectedDisk.SizeGB) GB)" -Options $borradoOptions

                    if ($tipoB -eq "V") { continue }

                    Clear-Host
                    Show-Logo -Subtitulo "BORRADO AVANZADO"
                    Write-Host ""
                    Write-Host "  Disco: $($selectedDisk.HWName) ($($selectedDisk.SizeGB) GB)" -ForegroundColor White
                    $tipoTexto = if ($tipoB -eq '2') { 'SEGURO (sobrescribir con ceros)' } else { 'RAPIDO' }
                    Write-Host "  Tipo: $tipoTexto" -ForegroundColor Yellow

                    # DOBLE CONFIRMACION
                    $actionDesc = "BORRAR ($tipoTexto) disco $($selectedDisk.DiskNumber) - $($selectedDisk.HWName)"
                    $targetDesc = "Disco $($selectedDisk.DiskNumber) - $($selectedDisk.HWName) ($($selectedDisk.SizeGB) GB)"

                    if (Confirm-CriticalAction -Action $actionDesc -Keyword "BORRAR" -TargetName $targetDesc -DangerLevel "danger") {
                            Write-Host ""

                            if ($tipoB -eq "2") {
                                # Borrado seguro con ceros
                                Write-Host "  [1/2] Limpiando disco (sobrescribiendo con ceros)..." -ForegroundColor Yellow
                                Write-Host "        Esto puede tardar mucho tiempo..." -ForegroundColor Gray

                                try {
                                    # Clear-Disk con -RemoveData -RemoveOEM y luego escribir ceros
                                    Clear-Disk -Number $selectedDisk.DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop

                                    Write-Host "  [2/2] Sobrescribiendo con ceros..." -ForegroundColor Yellow
                                    # Inicializar, crear particion y formatear con ceros
                                    Initialize-Disk -Number $selectedDisk.DiskNumber -PartitionStyle GPT -ErrorAction SilentlyContinue
                                    $part = New-Partition -DiskNumber $selectedDisk.DiskNumber -UseMaximumSize -ErrorAction SilentlyContinue

                                    if ($part) {
                                        # Formatear llena el disco de ceros
                                        Format-Volume -Partition $part -FileSystem NTFS -NewFileSystemLabel "Borrado" -Full -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
                                        # Luego limpiar de nuevo
                                        Clear-Disk -Number $selectedDisk.DiskNumber -RemoveData -Confirm:$false -ErrorAction SilentlyContinue
                                    }

                                    Write-Host ""
                                    Write-Host "  [OK] Disco borrado de forma segura" -ForegroundColor Green
                                    
                                    # Preguntar si inicializar
                                    Write-Host ""
                                    Write-Host "  ¿Inicializar y formatear el disco ahora? [S/N]: " -NoNewline -ForegroundColor Cyan
                                    $initDisk = Read-Host
                                    if ($initDisk -match "^[Ss]$") {
                                        # Llamar función de inicializar
                                        Initialize-AndFormatDisk -DiskNumber $selectedDisk.DiskNumber
                                    }
                                } catch {
                                    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                                }
                            } else {
                                # Borrado rapido
                                Write-Host "  Borrando particiones..." -ForegroundColor Yellow

                                # Verificar si el disco ya está sin inicializar
                                $diskCheck = Get-Disk -Number $selectedDisk.DiskNumber
                                if ($diskCheck.PartitionStyle -eq "RAW") {
                                    Write-Host ""
                                    Write-Host "  [OK] El disco ya esta vacio (sin inicializar)." -ForegroundColor Green
                                    Write-Host "  No hay nada que borrar." -ForegroundColor Gray
                                    
                                    # Preguntar si inicializar
                                    Write-Host ""
                                    Write-Host "  ¿Inicializar y formatear el disco ahora? [S/N]: " -NoNewline -ForegroundColor Cyan
                                    $initDisk = Read-Host
                                    if ($initDisk -match "^[Ss]$") {
                                        Initialize-AndFormatDisk -DiskNumber $selectedDisk.DiskNumber
                                    }
                                } else {
                                    try {
                                        Clear-Disk -Number $selectedDisk.DiskNumber -RemoveData -RemoveOEM -Confirm:$false -ErrorAction Stop
                                        Write-Host ""
                                        Write-Host "  [OK] Disco limpiado (borrado rapido)" -ForegroundColor Green
                                        Write-Host "  El disco esta ahora sin inicializar." -ForegroundColor Gray
                                        
                                        # Preguntar si inicializar
                                        Write-Host ""
                                        Write-Host "  ¿Inicializar y formatear el disco ahora? [S/N]: " -NoNewline -ForegroundColor Cyan
                                        $initDisk = Read-Host
                                        if ($initDisk -match "^[Ss]$") {
                                            Initialize-AndFormatDisk -DiskNumber $selectedDisk.DiskNumber
                                        }
                                    } catch {
                                        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
                                    }
                                }
                            }
                    }
                    Write-Host ""
                    Read-Host "  ENTER para continuar"
                }
            }
            "R" {
                # Refrescar Explorador de Windows
                Reset-WindowsExplorer
            }
            "6" {
                # Abrir logs con CMTrace
                $cmtracePath = "$PSScriptRoot\tools\CMTrace.exe"
                $logFolder = $script:CONFIG.LogPath

                if (Test-Path $cmtracePath) {
                    Write-Host ""
                    Write-Host "  Abriendo CMTrace..." -ForegroundColor Cyan

                    # Buscar el log más reciente
                    $latestLog = Get-ChildItem $logFolder -Filter "*.log" -ErrorAction SilentlyContinue |
                                 Sort-Object LastWriteTime -Descending |
                                 Select-Object -First 1

                    if ($latestLog) {
                        Start-Process $cmtracePath -ArgumentList "`"$($latestLog.FullName)`""
                        Write-Host "  Abierto: $($latestLog.Name)" -ForegroundColor Green
                    } else {
                        Start-Process $cmtracePath
                        Write-Host "  No hay logs todavia. CMTrace abierto vacio." -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds 1
                } else {
                    Write-Host ""
                    Write-Host "  CMTrace no encontrado en: $cmtracePath" -ForegroundColor Yellow
                    Write-Host "  Abriendo carpeta de logs..." -ForegroundColor Gray
                    if (Test-Path $logFolder) {
                        Start-Process explorer.exe -ArgumentList $logFolder
                    } else {
                        Write-Host "  No hay logs todavia." -ForegroundColor Yellow
                    }
                    Start-Sleep -Seconds 2
                }
            }
            "X" {
                Clear-Host
                Show-Logo
                Write-Host ""
                Write-Host "  Hasta pronto!" -ForegroundColor Cyan
                Write-Host ""
                return
            }
            default {
                Write-Host "  Opcion no valida. Usa 0-6 o X." -ForegroundColor Yellow
                Start-Sleep -Seconds 1
            }
        }

        Clear-Host
        Show-Logo
    }
}

# ===============================================================================
# EJECUTAR
# ===============================================================================

try {
    Show-Menu
} finally {
    # Restaurar servicio de deteccion de hardware al salir
    Enable-FormatPopups

    # Liberar MUTEX para permitir nuevas instancias
    if ($script:Mutex) {
        $script:Mutex.ReleaseMutex()
        $script:Mutex.Dispose()
    }
}



