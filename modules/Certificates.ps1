# Certificati radice aggiunti (T1553.004): permettono di leggere il traffico
# HTTPS (password, sessioni) o di far sembrare "firmato" un malware.

function Invoke-CheckCertificates {
    $cat = 'Certificati'
    $knownCa = '(?i)(Microsoft|DigiCert|GlobalSign|Sectigo|Comodo|COMODO|USERTrust|Entrust|ISRG|Internet Security Research|VeriSign|Thawte|thawte|GeoTrust|Baltimore|Starfield|Go Daddy|GoDaddy|QuoVadis|Certum|Unizeto|IdenTrust|Amazon|Google Trust|GTS Root|Symantec|Equifax|AddTrust|AAA Certificate|Actalis|Buypass|SwissSign|T-TeleSec|Deutsche Telekom|Telekom Security|Hellenic|HARICA|Izenpe|Microsec|NetLock|SECOM|Security Communication|SSL\.com|SSL Corporation|Trustwave|SecureTrust|XRamp|Network Solutions|Cybertrust|Class 3 Public Primary|Class 2 Public Primary|Copyright \(c\) 1997 Microsoft|NO LIABILITY ACCEPTED|Certainly|Atos|Autoridad de Certificacion|Firmaprofesional|ACCV|Chunghwa|Certigna|Dhimyotis|E-Tugra|emSign|GDCA|Hongkong Post|Japan Certification|KISA|TWCA|TUBITAK|UCA|Visa|SZAFIR|Trustis|TrustCor|D-TRUST|D-Trust|e-commerce monitoring|Asseco|ANF|AC RAIZ|Sonera|Telia|CFCA|Government|Staat der Nederlanden|DST Root|WISeKey|OISTE|Secom|LuxTrust|Certipost|Quovadis|InfoNotary|Disig|Camerfirma|Chambers of Commerce|Global Chambersign|Starfield|Apple|TeliaSonera|Cisco|Intel|Dell|HP |Hewlett|NVIDIA|AMD|Lenovo|XBL (Client|Server) IPsec|WFA Hotspot 2\.0|Hotspot 2\.0 Trust Root|Blizzard Entertainment|Kaspersky|NordVPN S\.A\.|ESET|Avast|AVG Technologies|Bitdefender|Norton|Gen Digital)'
    # Gli ultimi (antivirus e VPN) installano una radice per analizzare il traffico HTTPS:
    # e' normale se usi quel prodotto.

    # Radici aggiunte dall'utente (archivio fisico HKCU): quasi sempre un proxy/antivirus o un MITM
    foreach ($hu in Get-UserHives) {
        $p = "$($hu.Root)\Software\Microsoft\SystemCertificates\Root\Certificates"
        foreach ($k in Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue) {
            $blob = Get-RegValue $k.PSPath 'Blob'
            $subject = $k.PSChildName
            $cert = $null
            try {
                # Il Blob contiene proprieta' + certificato DER: cerchiamo l'inizio del DER (0x30 0x82)
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
            Add-InventoryItem $cat "Root utente | $($hu.User)" $subject
            if ($subject -match $knownCa) { continue }
            Add-Finding -Category $cat -Severity 'Medio' -Title "Certificato radice installato dall'utente: $subject" -Detail $p `
                -Evidence "Thumbprint $($k.PSChildName)$(if ($cert) { "; valido dal $($cert.NotBefore.ToString('dd/MM/yyyy')) al $($cert.NotAfter.ToString('dd/MM/yyyy'))" })" `
                -Mitre 'T1553.004' `
                -Reasons 'Un certificato radice permette a chi lo possiede di intercettare il traffico HTTPS. Normale solo per antivirus con scansione HTTPS, Fiddler/Burp, VPN aziendali.' `
                -Recommendation 'Apri certmgr.msc > Autorita'' di certificazione radice attendibili e rimuovilo se non lo riconosci.'
        }
    }

    # Radici della macchina con nomi non riconducibili a CA note
    foreach ($c in Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction SilentlyContinue) {
        Add-InventoryItem $cat 'Root macchina' "$($c.Thumbprint) $($c.Subject)"
        if ("$($c.Subject) $($c.Issuer)" -match $knownCa) { continue }
        $sev = 'Basso'
        $why = @("Nome dell'emittente non riconducibile a un'autorita' di certificazione nota.")
        if ($c.Subject -match '(?i)(localhost|DO_NOT_TRUST|proxy|mitm|fiddler|burp|charles|test|^CN=[^,=]{1,3}$)') { $sev = 'Medio'; $why += 'Il nome suggerisce un proxy di intercettazione o un certificato di test.' }
        if ($c.NotBefore -gt (Get-Date).AddDays(-180)) { $why += "Creato di recente ($($c.NotBefore.ToString('dd/MM/yyyy')))." }
        Add-Finding -Category $cat -Severity $sev -Title "Certificato radice non comune: $($c.Subject)" -Evidence "Thumbprint $($c.Thumbprint); emesso da $($c.Issuer)" `
            -Mitre 'T1553.004' -Reasons $why `
            -Recommendation 'Cerca il nome online: molti sono legittimi (driver, antivirus, software aziendale). Rimuovi da certlm.msc solo quelli che non riconosci.'
    }
}
