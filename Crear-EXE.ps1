# ===============================================================================
# Crear EXE portable para CLONADISCOS
# Compila un wrapper C# que ejecuta el script PowerShell
# ===============================================================================

$exePath = "$PSScriptRoot\CLONADISCOS.exe"
$icoPath = "$PSScriptRoot\clonadiscos.ico"
$ps1Path = "$PSScriptRoot\CLONADISCOS.ps1"

# Codigo C# del launcher
$csharpCode = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

class Program
{
    static void Main(string[] args)
    {
        string exeDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        string scriptPath = Path.Combine(exeDir, "CLONADISCOS.ps1");

        if (!File.Exists(scriptPath))
        {
            Console.WriteLine("ERROR: No se encuentra CLONADISCOS.ps1");
            Console.WriteLine("El archivo .exe debe estar junto al .ps1");
            Console.ReadKey();
            return;
        }

        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + scriptPath + "\"";
        psi.WorkingDirectory = exeDir;
        psi.UseShellExecute = true;
        psi.Verb = "runas"; // Ejecutar como admin

        try
        {
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
            Console.ReadKey();
        }
    }
}
"@

Write-Host ""
Write-Host "  Compilando CLONADISCOS.exe..." -ForegroundColor Cyan

# Buscar compilador C#
$cscPaths = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework64\v3.5\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v3.5\csc.exe"
)

$csc = $null
foreach ($path in $cscPaths) {
    if (Test-Path $path) {
        $csc = $path
        break
    }
}

if (-not $csc) {
    Write-Host "  [ERROR] No se encontro el compilador C# (csc.exe)" -ForegroundColor Red
    exit 1
}

Write-Host "  Usando: $csc" -ForegroundColor Gray

# Guardar codigo C# temporal
$tempCs = "$env:TEMP\CLONADISCOS_launcher.cs"
$csharpCode | Out-File -FilePath $tempCs -Encoding UTF8

# Compilar
$compileArgs = @(
    "/target:winexe",           # Aplicacion Windows (sin ventana de consola extra)
    "/out:`"$exePath`"",
    "/optimize+",
    "/platform:anycpu"
)

# Añadir icono si existe
if (Test-Path $icoPath) {
    $compileArgs += "/win32icon:`"$icoPath`""
    Write-Host "  Icono incluido: clonadiscos.ico" -ForegroundColor Gray
}

$compileArgs += "`"$tempCs`""

$process = Start-Process -FilePath $csc -ArgumentList $compileArgs -Wait -NoNewWindow -PassThru

# Limpiar temporal
Remove-Item $tempCs -Force -ErrorAction SilentlyContinue

if ($process.ExitCode -eq 0 -and (Test-Path $exePath)) {
    $size = [math]::Round((Get-Item $exePath).Length / 1KB, 1)
    Write-Host ""
    Write-Host "  [OK] CLONADISCOS.exe creado ($size KB)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Ahora puedes:" -ForegroundColor White
    Write-Host "    - Anclar a la barra de tareas" -ForegroundColor Gray
    Write-Host "    - Anclar al menu Inicio" -ForegroundColor Gray
    Write-Host "    - Copiar a cualquier PC (junto con .ps1 y .ico)" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "  [ERROR] Fallo la compilacion" -ForegroundColor Red
}
