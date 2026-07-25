@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path '.' -Recurse -File | ForEach-Object { try { $b = [System.IO.File]::ReadAllBytes($_.FullName); if ($b -notcontains 0) { $t = [System.Text.Encoding]::UTF8.GetString($b); $n = $t.Replace(\"`r`n\", \"`n\"); if ($t -ne $n) { [System.IO.File]::WriteAllText($_.FullName, $n, (New-Object System.Text.UTF8Encoding($false))); Write-Host ('Converted: ' + $_.FullName) } } } catch { Write-Host ('Error: ' + $_.Name) } }"
echo Conversion complete.
