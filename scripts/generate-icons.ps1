Add-Type -AssemblyName System.Drawing

$srcPath = "C:\Users\Kaan\.gemini\antigravity\brain\66fbe9c7-42fd-4138-b338-23fea6d131d8\.user_uploaded\media_1794420700394_aefa2775.png"

Copy-Item $srcPath "apps\desktop\public\logo.png" -Force
Copy-Item $srcPath "apps\desktop\public\aegis.png" -Force
Copy-Item $srcPath "apps\desktop\src-tauri\icons\icon.png" -Force

$srcBmp = [System.Drawing.Bitmap]::FromFile($srcPath)

function Resize-Bmp($bmp, $w, $h) {
    $t = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($t)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($bmp, 0, 0, $w, $h)
    $g.Dispose()
    return $t
}

$sizes = @(256, 128, 64, 48, 32, 16)
$pngBytesList = @()

foreach ($sz in $sizes) {
    $resized = Resize-Bmp $srcBmp $sz $sz
    if ($sz -eq 128) {
        $resized.Save("apps\desktop\src-tauri\icons\128x128.png", [System.Drawing.Imaging.ImageFormat]::Png)
    }
    if ($sz -eq 256) {
        $resized.Save("apps\desktop\src-tauri\icons\128x128@2x.png", [System.Drawing.Imaging.ImageFormat]::Png)
    }
    if ($sz -eq 32) {
        $resized.Save("apps\desktop\src-tauri\icons\32x32.png", [System.Drawing.Imaging.ImageFormat]::Png)
    }
    $ms = New-Object System.IO.MemoryStream
    $resized.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytesList += ,@($sz, $ms.ToArray())
    $ms.Dispose()
    $resized.Dispose()
}

$srcBmp.Dispose()

# Create .ico file with all resolutions
# ICO format:
# ICONDIR (6 bytes): 0, 0 (reserved), 1, 0 (type=icon), count, 0 (image count)
# ICONDIRENTRY (16 bytes each): width, height, colors, reserved, planes(2), bpp(2), size(4), offset(4)
# Followed by image data (PNG format for each)

function Write-IcoFile($outputPath, $images) {
    $fs = [System.IO.File]::Create($outputPath)
    $bw = New-Object System.IO.BinaryWriter($fs)
    
    $count = $images.Count
    $bw.Write([uint16]0) # Reserved
    $bw.Write([uint16]1) # Type 1 = Icon
    $bw.Write([uint16]$count) # Number of images
    
    $offset = 6 + (16 * $count)
    
    foreach ($item in $images) {
        $sz = $item[0]
        $bytes = $item[1]
        
        $w = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
        $h = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
        
        $bw.Write([byte]$w)
        $bw.Write([byte]$h)
        $bw.Write([byte]0) # Colors
        $bw.Write([byte]0) # Reserved
        $bw.Write([uint16]1) # Color planes
        $bw.Write([uint16]32) # Bits per pixel
        $bw.Write([uint32]$bytes.Length) # Image size
        $bw.Write([uint32]$offset) # Offset
        
        $offset += $bytes.Length
    }
    
    foreach ($item in $images) {
        $bw.Write($item[1])
    }
    
    $bw.Flush()
    $bw.Close()
    $fs.Close()
}

Write-IcoFile "apps\desktop\public\icon.ico" $pngBytesList
Write-IcoFile "apps\desktop\src-tauri\icons\icon.ico" $pngBytesList

Write-Host "Multi-resolution icon.ico and PNGs generated successfully!"

