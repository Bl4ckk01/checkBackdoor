# Optional hash lookup on VirusTotal. ONLY the SHA-256 hash (a fingerprint of the file)
# is sent, never the file itself. A free API key is needed.

function Invoke-VirusTotalLookup {
    param([string]$ApiKey, [int]$Max = 20, [switch]$IncludeInfo)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $hashes = @($script:Findings |
        Where-Object { $_.Sha256 -and ($IncludeInfo -or $_.Severity -ne 'Info') -and -not (Test-MicrosoftSigner $_.Signer) } |
        Select-Object -ExpandProperty Sha256 -Unique | Select-Object -First $Max)
    if (-not $hashes) { return }

    $results = @{}
    for ($i = 0; $i -lt $hashes.Count; $i++) {
        $h = $hashes[$i]
        Write-Progress -Activity 'VirusTotal' -Status "Hash $($i + 1) of $($hashes.Count) (free API limit: 4 per minute)" -PercentComplete (100 * $i / $hashes.Count)
        if ($i -gt 0) { Start-Sleep -Seconds 16 }
        try {
            $r = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$h" -Headers @{ 'x-apikey' = $ApiKey } -ErrorAction Stop
            $st = $r.data.attributes.last_analysis_stats
            $label = $null
            try { $label = $r.data.attributes.popular_threat_classification.suggested_threat_label } catch { }
            $results[$h] = [pscustomobject]@{
                Known = $true; Malicious = [int]$st.malicious; Suspicious = [int]$st.suspicious
                Total = [int]$st.malicious + [int]$st.suspicious + [int]$st.undetected + [int]$st.harmless
                Label = $label; Link = "https://www.virustotal.com/gui/file/$h"
            }
        } catch {
            $code = $null
            try { $code = [int]$_.Exception.Response.StatusCode } catch { }
            if ($code -eq 404) {
                $results[$h] = [pscustomobject]@{ Known = $false; Malicious = 0; Suspicious = 0; Total = 0; Label = $null; Link = "https://www.virustotal.com/gui/file/$h" }
            } elseif ($code -in 401, 403) {
                Write-ScanWarning 'Invalid VirusTotal API key: lookup skipped.'
                break
            } elseif ($code -eq 429) {
                Write-ScanWarning 'VirusTotal request limit reached: lookup stopped.'
                break
            }
        }
    }
    Write-Progress -Activity 'VirusTotal' -Completed

    foreach ($f in $script:Findings) {
        if (-not $f.Sha256 -or -not $results.ContainsKey($f.Sha256)) { continue }
        $vt = $results[$f.Sha256]
        $f.VirusTotal = $vt
        if (-not $vt.Known) {
            $f.Reasons = @($f.Reasons) + 'VirusTotal has never seen this file: it is rare or made specifically for you (upload it by hand for an analysis)'
        } elseif ($vt.Malicious -ge 5) {
            $f.Severity = 'High'
            $f.Reasons = @("VirusTotal: $($vt.Malicious)/$($vt.Total) antivirus engines consider it malicious$(if ($vt.Label) { " ($($vt.Label))" })") + @($f.Reasons)
        } elseif ($vt.Malicious -ge 1 -or $vt.Suspicious -ge 2) {
            if ($f.Severity -in 'Low', 'Info') { $f.Severity = 'Medium' }
            $f.Reasons = @("VirusTotal: $($vt.Malicious) malicious and $($vt.Suspicious) suspicious detections out of $($vt.Total) (a few detections can be false positives, especially for cracks and tools)") + @($f.Reasons)
        } else {
            $f.Reasons = @("VirusTotal: 0/$($vt.Total) detections") + @($f.Reasons)
        }
        # Same ID, updated severity and reasons: the app replaces the finding
        Write-ScanEvent 'finding.updated' ([ordered]@{ check = 'VirusTotal'; finding = $f })
    }
}
