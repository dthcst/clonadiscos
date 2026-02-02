$file = "E:\_MEMMEM\_APPS\CLONADISCOS\_DEV\CLONADISCOS.ps1"
$content = Get-Content $file
$before = $content[0..2084]
$after = $content[2536..($content.Count-1)]
$newContent = $before + $after
$newContent | Set-Content $file -Encoding UTF8
Write-Host "Eliminadas $($content.Count - $newContent.Count) lineas"
Write-Host "Antes: $($content.Count) lineas"
Write-Host "Ahora: $($newContent.Count) lineas"
