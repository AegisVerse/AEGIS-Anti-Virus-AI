Add-Type -AssemblyName System.Drawing
$srcPath = "C:\Users\Kaan\.gemini\antigravity\brain\66fbe9c7-42fd-4138-b338-23fea6d131d8\.user_uploaded\media_1794420700394_aefa2775.png"
$srcBmp = [System.Drawing.Bitmap]::FromFile($srcPath)

function Resize-Img($bmp, $w, $h, $out) {
    $t = New-Object System.Drawing.Bitmap($w, $h)
    $g = [System.Drawing.Graphics]::FromImage($t)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($bmp, 0, 0, $w, $h)
    $g.Dispose()
    $t.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
    $t.Dispose()
}

Resize-Img $srcBmp 16 16 "browser-extension\icons\icon-16.png"
Resize-Img $srcBmp 32 32 "browser-extension\icons\icon-32.png"
Resize-Img $srcBmp 48 48 "browser-extension\icons\icon-48.png"
Resize-Img $srcBmp 128 128 "browser-extension\icons\icon-128.png"
$srcBmp.Dispose()
Write-Host "Browser extension icons generated successfully!"

