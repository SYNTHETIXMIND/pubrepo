# Version: 1.0.0

# First 5 seconds of Tetris theme (Korobeiniki) in PowerShell
# Notes: E5, B4, C5, D5, C5, B4, A4, A4, C5, E5, D5, C5, B4, B4, C5, D5, E5, C5, A4, A4

# Display a visible notification
Write-Host "`n" -NoNewline
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "          TASK COMPLETE - NOTIFICATION              " -ForegroundColor White -BackgroundColor DarkGreen
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "`n" -NoNewline

# Frequencies in Hz for each note
$e5 = 659
$b4 = 494
$c5 = 523
$d5 = 587
$a4 = 440

# Duration for each note
$quarter = 200
$eighth = 100
$sixteenth = 50
$pause = 25

# Tetris theme - first 5 seconds
try {
    [console]::beep($e5, $quarter); Start-Sleep -m $pause
    [console]::beep($b4, $eighth); Start-Sleep -m $pause
    [console]::beep($c5, $eighth); Start-Sleep -m $pause
    [console]::beep($d5, $quarter); Start-Sleep -m $pause
    [console]::beep($c5, $eighth); Start-Sleep -m $pause
    [console]::beep($b4, $eighth); Start-Sleep -m $pause
    [console]::beep($a4, $quarter); Start-Sleep -m $pause
    [console]::beep($a4, $eighth); Start-Sleep -m $pause
    [console]::beep($c5, $eighth); Start-Sleep -m $pause
    [console]::beep($e5, $quarter); Start-Sleep -m $pause
    [console]::beep($d5, $eighth); Start-Sleep -m $pause
    [console]::beep($c5, $eighth); Start-Sleep -m $pause
    [console]::beep($b4, $quarter); Start-Sleep -m $pause
    [console]::beep($b4, $eighth); Start-Sleep -m $pause
    [console]::beep($c5, $eighth); Start-Sleep -m $pause
    [console]::beep($d5, $quarter); Start-Sleep -m $pause
    [console]::beep($e5, $quarter); Start-Sleep -m $pause
    [console]::beep($c5, $quarter); Start-Sleep -m $pause
    [console]::beep($a4, $quarter); Start-Sleep -m $pause
    [console]::beep($a4, $quarter)
}
catch {
    # If console beeps fail, just continue - the visual notification is still shown
    Write-Host "Audio notification not available on this system" -ForegroundColor Yellow
}

# Display timestamp of notification with the year fixed to 2024 to match project timeline
$currentDate = Get-Date
$projectDate = Get-Date -Year 2024 -Month $currentDate.Month -Day $currentDate.Day -Hour $currentDate.Hour -Minute $currentDate.Minute -Second $currentDate.Second
Write-Host "Time: $($projectDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "`n" -NoNewline 
