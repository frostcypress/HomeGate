# Run on the computer/connection that actually accesses the public service.
param()
$ErrorActionPreference = 'Continue'
$reportPath = Join-Path $PSScriptRoot ('homegate-client-network-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('HomeGate client egress diagnostic v1; read-only HTTP requests; no DNS credentials')
$lines.Add('UTC ' + [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
$lines.Add('Cloudflare loc describes this request egress; VPN/proxy routes may differ from physical location.')
$curlTool = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($curlTool) {
    foreach ($family in @('auto', '4', '6')) {
        $lines.Add('--- client egress ' + $family + ' ---')
        $curlArgs = @('--noproxy', '*', '--silent', '--show-error', '--connect-timeout', '8', '--max-time', '18')
        if ($family -ne 'auto') { $curlArgs += ('-' + $family) }
        $curlArgs += 'https://www.cloudflare.com/cdn-cgi/trace'
        $result = @(& $curlTool.Source @curlArgs 2>&1)
        $code = $LASTEXITCODE
        foreach ($entry in $result) {
            $entryText = [string]$entry
            if ($entryText -match '^(ip|loc|colo|warp)=') { $lines.Add($entryText) }
            elseif ($code -ne 0) { $lines.Add($entryText) }
        }
        $lines.Add('exit=' + $code)
    }
} else {
    $lines.Add('SKIP curl.exe missing; no software installed')
}
$lines.Add('--- Windows HTTP stack (system proxy may apply) ---')
try {
    $internetSettings = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $lines.Add('system_proxy_enabled=' + [bool]$internetSettings.ProxyEnable)
    $lines.Add('system_proxy_server_present=' + [bool]$internetSettings.ProxyServer)
    $lines.Add('system_proxy_pac_present=' + [bool]$internetSettings.AutoConfigURL)
    $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://www.cloudflare.com/cdn-cgi/trace' -TimeoutSec 18 -ErrorAction Stop
    foreach ($entryText in ([string]$response.Content -split "`n")) {
        if ($entryText -match '^(ip|loc|colo|warp)=') { $lines.Add($entryText.Trim()) }
    }
} catch {
    $lines.Add('HTTP_STACK_ERROR=' + $_.Exception.Message)
}
$lines.Add('curl probes use direct HTTP connections (VPN routes still apply). Windows HTTP stack may use system proxy. Browser-specific proxy/PAC behavior can still differ; actual HomeGate access records are the deciding evidence.')
$lines.Add('This does not test a service URL or change HomeGate access policy. Send this log together with the router archive.')
[IO.File]::WriteAllLines($reportPath, $lines, [Text.UTF8Encoding]::new($false))
Write-Output ('REPORT ' + $reportPath)
