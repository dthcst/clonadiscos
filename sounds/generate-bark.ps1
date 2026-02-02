# Generar ladrido sintetico (WAV)
$sampleRate = 44100
$duration = 0.25
$samples = [int]($sampleRate * $duration)

$audioData = New-Object byte[] ($samples * 2)

for ($i = 0; $i -lt $samples; $i++) {
    $t = $i / $sampleRate
    # Frecuencia que sube y baja (como un ladrido)
    $freq = 500 + 400 * [Math]::Sin($t * 40) + 200 * [Math]::Sin($t * 20)
    # Envolvente (ataque rapido, decay)
    $envelope = [Math]::Exp(-$t * 10) * [Math]::Min(1, $t * 80)
    # Onda
    $sample = $envelope * [Math]::Sin(2 * [Math]::PI * $freq * $t) * 0.9

    $value = [int]($sample * 32767)
    $value = [Math]::Max(-32768, [Math]::Min(32767, $value))

    $audioData[$i * 2] = $value -band 0xFF
    $audioData[$i * 2 + 1] = ($value -shr 8) -band 0xFF
}

# Crear archivo WAV
$wavPath = "$PSScriptRoot\bark.wav"
$fs = [System.IO.FileStream]::new($wavPath, [System.IO.FileMode]::Create)
$bw = [System.IO.BinaryWriter]::new($fs)

# Header WAV
$bw.Write([byte[]][char[]]"RIFF")
$bw.Write([int](36 + $audioData.Length))
$bw.Write([byte[]][char[]]"WAVE")
$bw.Write([byte[]][char[]]"fmt ")
$bw.Write([int]16)
$bw.Write([int16]1)
$bw.Write([int16]1)
$bw.Write([int]$sampleRate)
$bw.Write([int]($sampleRate * 2))
$bw.Write([int16]2)
$bw.Write([int16]16)
$bw.Write([byte[]][char[]]"data")
$bw.Write([int]$audioData.Length)
$bw.Write($audioData)

$bw.Close()
$fs.Close()

Write-Host "[OK] bark.wav generado en $wavPath" -ForegroundColor Green
