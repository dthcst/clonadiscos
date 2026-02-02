# Fix para disco que no aparece en Explorer

Write-Host ""
Write-Host "  Reparando visibilidad del disco..." -ForegroundColor Cyan
Write-Host ""

# 1. Verificar politicas que ocultan unidades
$policyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
if (Test-Path $policyPath) {
    $nodrives = Get-ItemProperty $policyPath -Name NoDrives -ErrorAction SilentlyContinue
    if ($nodrives.NoDrives) {
        Write-Host "  [!] Politica NoDrives activa: $($nodrives.NoDrives)" -ForegroundColor Yellow
        Write-Host "  Eliminando politica..." -ForegroundColor Gray
        Remove-ItemProperty $policyPath -Name NoDrives -ErrorAction SilentlyContinue
    }
}

# 2. Reasignar letra para forzar deteccion
Write-Host "  Reasignando letra F:..." -ForegroundColor Gray
try {
    Remove-PartitionAccessPath -DiskNumber 2 -PartitionNumber 2 -AccessPath 'F:\' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Add-PartitionAccessPath -DiskNumber 2 -PartitionNumber 2 -AccessPath 'F:\' -ErrorAction SilentlyContinue
    Write-Host "  [OK] Letra reasignada" -ForegroundColor Green
} catch {
    Write-Host "  [!] Error: $_" -ForegroundColor Yellow
}

# 3. Refrescar shell
Write-Host "  Refrescando Explorer..." -ForegroundColor Gray
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-Process explorer

Write-Host ""
Write-Host "  [OK] Explorer reiniciado - mira si aparece F: ahora" -ForegroundColor Green
Write-Host ""
