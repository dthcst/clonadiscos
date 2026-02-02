$errors = $null
$tokens = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot\CLONADISCOS.ps1", [ref]$tokens, [ref]$errors)
if ($errors.Count -eq 0) {
    Write-Host "[OK] CLONADISCOS.ps1 - Sintaxis correcta" -ForegroundColor Green
    exit 0
} else {
    Write-Host "[ERRORES] $($errors.Count) errores encontrados:" -ForegroundColor Red
    foreach ($e in $errors) {
        Write-Host "  Linea $($e.Extent.StartLineNumber): $($e.Message)" -ForegroundColor Red
    }
    exit 1
}
