# Compilar instalador CLONADISCOS con Inno Setup

$issFile = "$PSScriptRoot\CLONADISCOS-Setup.iss"

# Buscar ISCC.exe
$isccPaths = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe"
)

$iscc = $null
foreach ($path in $isccPaths) {
    if (Test-Path $path) {
        $iscc = $path
        break
    }
}

if (-not $iscc) {
    Write-Host "[ERROR] No se encontro Inno Setup (ISCC.exe)" -ForegroundColor Red
    Write-Host "Rutas buscadas:" -ForegroundColor Gray
    $isccPaths | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
    exit 1
}

Write-Host ""
Write-Host "  Compilando instalador CLONADISCOS..." -ForegroundColor Cyan
Write-Host "  ISCC: $iscc" -ForegroundColor Gray
Write-Host ""

# Crear carpeta Output
$outputDir = "$PSScriptRoot\Output"
if (-not (Test-Path $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

# Compilar
& $iscc $issFile

if ($LASTEXITCODE -eq 0) {
    $setupFile = Get-ChildItem "$outputDir\*.exe" | Select-Object -First 1
    Write-Host ""
    Write-Host "  [OK] Instalador creado:" -ForegroundColor Green
    Write-Host "  $($setupFile.FullName)" -ForegroundColor White
    Write-Host "  Tamano: $([math]::Round($setupFile.Length / 1MB, 2)) MB" -ForegroundColor Gray
} else {
    Write-Host ""
    Write-Host "  [ERROR] Fallo la compilacion" -ForegroundColor Red
}
