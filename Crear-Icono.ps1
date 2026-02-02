# ===============================================================================
# Generador de Icono para CLONADISCOS
# Crea un icono de 256x256 con dos discos y una flecha
# ===============================================================================

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$sizes = @(16, 32, 48, 64, 128, 256)
$outputPath = "$PSScriptRoot\clonadiscos.ico"

# Crear bitmap principal (256x256)
$bmp = New-Object System.Drawing.Bitmap(256, 256)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

# Colores
$diskColor1 = [System.Drawing.Color]::FromArgb(255, 0, 180, 200)     # CYAN (origen)
$diskColor2 = [System.Drawing.Color]::FromArgb(255, 245, 245, 245)   # BLANCO (destino)
$arrowColor = [System.Drawing.Color]::FromArgb(255, 0, 200, 100)     # Verde
$labelColor = [System.Drawing.Color]::FromArgb(255, 100, 180, 255)   # Azul claro
$highlightColor = [System.Drawing.Color]::FromArgb(255, 255, 200, 0) # Amarillo

# Pinceles y lapices
$brushDisk1 = New-Object System.Drawing.SolidBrush($diskColor1)
$brushDisk2 = New-Object System.Drawing.SolidBrush($diskColor2)
$brushArrow = New-Object System.Drawing.SolidBrush($arrowColor)
$brushLabel = New-Object System.Drawing.SolidBrush($labelColor)
$brushHighlight = New-Object System.Drawing.SolidBrush($highlightColor)
$penBorder = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 40, 40, 40), 3)

# ─── DISCO ORIGEN (izquierda arriba) ───
$disk1X = 20
$disk1Y = 30
$diskW = 90
$diskH = 70

# Cuerpo del disco
$g.FillRectangle($brushDisk1, $disk1X, $disk1Y, $diskW, $diskH)
$g.DrawRectangle($penBorder, $disk1X, $disk1Y, $diskW, $diskH)

# Etiqueta del disco
$g.FillRectangle($brushLabel, $disk1X + 10, $disk1Y + 10, $diskW - 20, 15)

# LED (verde = activo)
$g.FillEllipse($brushArrow, $disk1X + 15, $disk1Y + 50, 10, 10)

# ─── DISCO DESTINO (derecha abajo) ───
$disk2X = 145
$disk2Y = 155
$g.FillRectangle($brushDisk2, $disk2X, $disk2Y, $diskW, $diskH)
$g.DrawRectangle($penBorder, $disk2X, $disk2Y, $diskW, $diskH)
$g.FillRectangle($brushLabel, $disk2X + 10, $disk2Y + 10, $diskW - 20, 15)
$g.FillEllipse($brushHighlight, $disk2X + 15, $disk2Y + 50, 10, 10)

# ─── RAYO AMARILLO FOSFORITO RETRO ───
$rayoColor = [System.Drawing.Color]::FromArgb(255, 255, 255, 0)      # Amarillo fosforito
$rayoBorde = [System.Drawing.Color]::FromArgb(255, 220, 180, 0)      # Borde dorado
$brushRayo = New-Object System.Drawing.SolidBrush($rayoColor)
$penRayoBorde = New-Object System.Drawing.Pen($rayoBorde, 3)

# Rayo en zigzag MAS ANCHO (estilo retro)
$rayoPoints = @(
    [System.Drawing.Point]::new(108, 80),   # Punta superior izq
    [System.Drawing.Point]::new(128, 80),   # Punta superior der
    [System.Drawing.Point]::new(145, 115),  # Zigzag derecha
    [System.Drawing.Point]::new(125, 115),  # Muesca interior
    [System.Drawing.Point]::new(155, 165),  # Punta inferior der
    [System.Drawing.Point]::new(135, 165),  # Punta inferior izq
    [System.Drawing.Point]::new(120, 130),  # Zigzag izquierda
    [System.Drawing.Point]::new(140, 130),  # Muesca interior
    [System.Drawing.Point]::new(108, 80)    # Cerrar
)
$g.FillPolygon($brushRayo, $rayoPoints)
$g.DrawPolygon($penRayoBorde, $rayoPoints)

# Limpiar recursos
$g.Dispose()

# Guardar como PNG primero (para preview)
$pngPath = "$PSScriptRoot\clonadiscos-preview.png"
$bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
Write-Host "[OK] Preview guardado: $pngPath" -ForegroundColor Green

# Convertir a ICO (multi-resolucion)
# Nota: Para ICO real multi-size, necesitariamos IconLib o similar
# Por ahora guardamos como ICO basico (256x256)
$iconPath = "$PSScriptRoot\clonadiscos.ico"

# Crear icono desde bitmap
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())

# Guardar como archivo .ico
$fs = [System.IO.File]::OpenWrite($iconPath)
$icon.Save($fs)
$fs.Close()

Write-Host "[OK] Icono guardado: $iconPath" -ForegroundColor Green

# Limpiar
$bmp.Dispose()
$icon.Dispose()

Write-Host ""
Write-Host "Icono creado con exito!" -ForegroundColor Cyan
Write-Host "  - Preview: clonadiscos-preview.png"
Write-Host "  - Icono:   clonadiscos.ico"
