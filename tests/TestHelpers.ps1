# Shared test support: load it with  . "$PSScriptRoot\TestHelpers.ps1"
# (Invoke-Tests.ps1 starts the tests from a path without [ ], so this works).
# Modules are loaded by reading their text, as CheckBackdoor.ps1 does.
#
# The malicious command samples in the tests are harmless and assembled at runtime: written
# out in full (a Base64 download, certutil -urlcache) they would get the file blocked by AMSI.

$script:ProjectRoot = Split-Path -Parent $PSScriptRoot

# Base64 of a harmless command, as long as a real payload
function New-HarmlessEncodedCommand {
    [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "CheckBackdoor test"; Start-Sleep 0'))
}

function Get-ModuleScript {
    param([Parameter(Mandatory)][string]$Name)
    [scriptblock]::Create([IO.File]::ReadAllText((Join-Path $script:ProjectRoot "modules\$Name.ps1")))
}

# A minimal finding, with the fields Add-Finding produces
function New-TestFinding {
    param([string]$Severity = 'Medium', [string]$Category = 'Autostart', [string]$Title = 'Test entry', [string]$Path, [string]$Evidence, [string[]]$Reasons = @('Test reason'), [string]$Sha256)
    [pscustomobject]@{
        Id = (Get-FindingId $Category $Title $Path $Evidence); Check = 'Test'
        Category = $Category; Severity = $Severity; Title = $Title; Detail = $null; Path = $Path; Evidence = $Evidence
        Mitre = 'T1547.001'; Recommendation = 'Test advice'; Reasons = $Reasons; Sha256 = $Sha256; Signer = $null; VirusTotal = $null
    }
}
