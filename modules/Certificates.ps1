# Added root certificates (T1553.004): they allow reading HTTPS traffic (passwords,
# sessions) or making malware look "signed".

function Invoke-CheckCertificates {
    $cat = 'Certificates'
    $knownCa = '(?i)(Microsoft|DigiCert|GlobalSign|Sectigo|Comodo|COMODO|USERTrust|Entrust|ISRG|Internet Security Research|VeriSign|Thawte|thawte|GeoTrust|Baltimore|Starfield|Go Daddy|GoDaddy|QuoVadis|Certum|Unizeto|IdenTrust|Amazon|Google Trust|GTS Root|Symantec|Equifax|AddTrust|AAA Certificate|Actalis|Buypass|SwissSign|T-TeleSec|Deutsche Telekom|Telekom Security|Hellenic|HARICA|Izenpe|Microsec|NetLock|SECOM|Security Communication|SSL\.com|SSL Corporation|Trustwave|SecureTrust|XRamp|Network Solutions|Cybertrust|Class 3 Public Primary|Class 2 Public Primary|Copyright \(c\) 1997 Microsoft|NO LIABILITY ACCEPTED|Certainly|Atos|Autoridad de Certificacion|Firmaprofesional|ACCV|Chunghwa|Certigna|Dhimyotis|E-Tugra|emSign|GDCA|Hongkong Post|Japan Certification|KISA|TWCA|TUBITAK|UCA|Visa|SZAFIR|Trustis|TrustCor|D-TRUST|D-Trust|e-commerce monitoring|Asseco|ANF|AC RAIZ|Sonera|Telia|CFCA|Government|Staat der Nederlanden|DST Root|WISeKey|OISTE|Secom|LuxTrust|Certipost|Quovadis|InfoNotary|Disig|Camerfirma|Chambers of Commerce|Global Chambersign|Starfield|Apple|TeliaSonera|Cisco|Intel|Dell|HP |Hewlett|NVIDIA|AMD|Lenovo|XBL (Client|Server) IPsec|WFA Hotspot 2\.0|Hotspot 2\.0 Trust Root|Blizzard Entertainment|Kaspersky|NordVPN S\.A\.|ESET|Avast|AVG Technologies|Bitdefender|Norton|Gen Digital)'
    # The last ones (antivirus and VPN products) install a root to inspect HTTPS traffic:
    # normal if you use that product.

    # Roots added by the user (HKCU physical store): almost always a proxy/antivirus or a MITM
    foreach ($hu in Get-UserHives) {
        $p = "$($hu.Root)\Software\Microsoft\SystemCertificates\Root\Certificates"
        foreach ($k in Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue) {
            $blob = Get-RegValue $k.PSPath 'Blob'
            $subject = $k.PSChildName
            $cert = $null
            try {
                # The Blob holds properties + the DER certificate: look for the DER start (0x30 0x82)
                for ($i = 0; $i -lt $blob.Length - 4; $i++) {
                    if ($blob[$i] -eq 0x30 -and $blob[$i + 1] -eq 0x82) {
                        $len = ($blob[$i + 2] * 256) + $blob[$i + 3] + 4
                        if ($i + $len -le $blob.Length) {
                            $der = New-Object byte[] $len
                            [Array]::Copy($blob, $i, $der, 0, $len)
                            try { $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $der); break } catch { }
                        }
                    }
                }
            } catch { }
            if ($cert) { $subject = $cert.Subject }
            Add-InventoryItem $cat "User root | $($hu.User)" $subject
            if ($subject -match $knownCa) { continue }
            Add-Finding -Category $cat -Severity 'Medium' -Title "Root certificate installed by the user: $subject" -Detail $p `
                -Evidence "Thumbprint $($k.PSChildName)$(if ($cert) { "; valid from $($cert.NotBefore.ToString('yyyy-MM-dd')) to $($cert.NotAfter.ToString('yyyy-MM-dd'))" })" `
                -Mitre 'T1553.004' `
                -Reasons 'A root certificate lets whoever owns it intercept HTTPS traffic. Normal only for antivirus with HTTPS scanning, Fiddler/Burp, company VPNs.' `
                -Recommendation 'Open certmgr.msc > Trusted Root Certification Authorities and remove it if you do not recognise it.'
        }
    }

    # Machine roots whose names do not match a known CA
    foreach ($c in Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction SilentlyContinue) {
        Add-InventoryItem $cat 'Machine root' "$($c.Thumbprint) $($c.Subject)"
        if ("$($c.Subject) $($c.Issuer)" -match $knownCa) { continue }
        $sev = 'Low'
        $why = @('The issuer name does not match a known certification authority.')
        if ($c.Subject -match '(?i)(localhost|DO_NOT_TRUST|proxy|mitm|fiddler|burp|charles|test|^CN=[^,=]{1,3}$)') { $sev = 'Medium'; $why += 'The name suggests an interception proxy or a test certificate.' }
        if ($c.NotBefore -gt (Get-Date).AddDays(-180)) { $why += "Created recently ($($c.NotBefore.ToString('yyyy-MM-dd')))." }
        Add-Finding -Category $cat -Severity $sev -Title "Uncommon root certificate: $($c.Subject)" -Evidence "Thumbprint $($c.Thumbprint); issued by $($c.Issuer)" `
            -Mitre 'T1553.004' -Reasons $why `
            -Recommendation 'Search the name online: many are legitimate (drivers, antivirus, company software). Remove from certlm.msc only those you do not recognise.'
    }
}
