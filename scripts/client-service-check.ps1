# Run on the computer using the failing VPN/node. No install or configuration writes.
param([string]$TargetsFile = (Join-Path $PSScriptRoot 'service-targets.txt'))
$ErrorActionPreference = 'Continue'
$reportPath = Join-Path $PSScriptRoot ('homegate-client-service-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
$lines = [Collections.Generic.List[string]]::new()
$lines.Add('role=client; UTC=' + [DateTime]::UtcNow.ToString('o'))
$lines.Add('Use the same VPN/node as the failing browser. Direct probes bypass HTTP proxies; VPN routes still apply.')
if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'client-network-check.ps1')) {
    $egressOutput = @(& (Join-Path $PSScriptRoot 'client-network-check.ps1'))
    foreach ($entry in $egressOutput) {
        if ([string]$entry -like 'REPORT *') {
            $egressPath = ([string]$entry).Substring(7)
            if (Test-Path -LiteralPath $egressPath) {
                $lines.Add('--- client egress / proxy context ---')
                foreach ($line in (Get-Content -LiteralPath $egressPath)) { $lines.Add([string]$line) }
            }
        }
    }
} else { $lines.Add('SKIP egress helper missing') }
if (!(Test-Path -LiteralPath $TargetsFile)) { throw 'Missing service-targets.txt; copy it from the router diagnostic report.' }
$curlTool = Get-Command curl.exe -ErrorAction SilentlyContinue
$targets = @(Get-Content -LiteralPath $TargetsFile | Where-Object { $_.Trim() } | Select-Object -First 32)
foreach ($target in $targets) {
    $uri = $null
    if (![Uri]::TryCreate($target.Trim(), [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -notin @('http','https') -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or $uri.AbsolutePath -ne '/' -or $uri.Host -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]*$') {
        $lines.Add('SKIP invalid target'); continue
    }
    $lines.Add('TARGET=' + $uri.AbsoluteUri)
    foreach ($type in @('A','AAAA')) {
        try {
            $answers = @(Resolve-DnsName -Name $uri.Host -Type $type -DnsOnly -ErrorAction Stop)
            $ips = @($answers | Where-Object IPAddress | ForEach-Object IPAddress)
            $lines.Add('DNS_' + $type + '=' + ($ips -join ','))
        } catch { $lines.Add('DNS_' + $type + '_ERROR=' + $_.Exception.Message) }
    }
    if ($curlTool) {
        foreach ($route in @('direct','environment-proxy')) {
            foreach ($family in @('4','6')) {
                $lines.Add('route=' + $route + '; family=' + $family)
                $probeArgs = @(('-' + $family),'--head','--silent','--show-error','--connect-timeout','5','--max-time','10','--output','NUL','--write-out',"http_code=%{http_code}\nremote_ip=%{remote_ip}\nssl_verify_result=%{ssl_verify_result}\n")
                if ($route -eq 'direct') { $probeArgs += @('--noproxy','*') }
                $probeArgs += $uri.AbsoluteUri
                @(& $curlTool.Source @probeArgs 2>&1) | ForEach-Object { $lines.Add([string]$_) }
                $lines.Add('curl_exit=' + $LASTEXITCODE)
            }
        }
    } else { $lines.Add('SKIP curl.exe missing') }
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Head -Uri $uri.AbsoluteUri -TimeoutSec 10 -MaximumRedirection 0 -ErrorAction Stop
        $lines.Add('system_http_status=' + [int]$response.StatusCode)
    } catch {
        $lines.Add('system_http_error=' + $_.Exception.Message)
        if ($_.Exception.Response) { $lines.Add('system_http_status=' + [int]$_.Exception.Response.StatusCode) }
    }
}
$lines.Add('curl: 6=DNS,7=connection,28=timeout,35=TLS handshake,60=certificate; HTTP 401/403/404/405 still proves HTTP reachability.')
$lines.Add('Proxy-family probes can describe the connection to the proxy, not its target. Windows HTTP stack and browser/mobile proxy routing can differ.')
$lines.Add('Pair this report with router access records. No entry can also mean firewall/TLS failure before HTTP logging.')
[IO.File]::WriteAllLines($reportPath, $lines, [Text.UTF8Encoding]::new($false))
Write-Output ('REPORT ' + $reportPath)
