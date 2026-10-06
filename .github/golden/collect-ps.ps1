# collect-ps.ps1 — coleta goldens PowerShell em runner descartavel (GitHub windows-latest).
# NAO executa nada no host do dev: este script so roda dentro do workflow.
# Entrada: ws155_calls.jsonl {uuid,idx,tool,arguments.command}
# Saida:  out/ps_results.jsonl {uuid,idx,tool,command,ok,exit_code,stdout,stderr,refused}
# Seguranca: blocklist antes de executar + processo filho com timeout 20s + truncate 32KB.
param(
  [string]$Calls = (Join-Path $PSScriptRoot "ws155_calls.jsonl"),
  [string]$Out = (Join-Path (Join-Path $PSScriptRoot "out") "ps_results.jsonl")
)

$TIMEOUT_S = 20
$MAX_CHARS = 32768
$BLOCK = [regex]::new(
  "(invoke-expression|\biex\b|invoke-webrequest|invoke-restmethod|\birw\b|\bcurl\b|" +
  "invoke-shellcode|mimikatz|sekurlsa|rubeus|kerberoast|meterpreter|" +
  "remove-item|\bdel\b|\brd\b|format-|stop-computer|restart-computer|new-service|" +
  "set-executionpolicy|start-process|amsi|defender)",
  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$lines = Get-Content -LiteralPath $Calls -Encoding UTF8 | Where-Object { $_.Trim() }
$nOk = 0; $nErr = 0; $nRef = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$outLines = @()
$i = 0
foreach ($line in $lines) {
  $i++
  $c = $line | ConvertFrom-Json
  $cmd = [string]$c.arguments.command
  $refused = ""
  $ok = $false; $code = -1; $so = ""; $se = ""
  if ([string]::IsNullOrWhiteSpace($cmd)) {
    $refused = "empty command"
  } elseif ($BLOCK.IsMatch($cmd)) {
    $refused = "REFUSED by collector blocklist"
  } else {
    $soFile = [System.IO.Path]::GetTempFileName()
    $seFile = [System.IO.Path]::GetTempFileName()
    try {
      $p = Start-Process -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-Command", $cmd) `
        -NoNewWindow -PassThru `
        -RedirectStandardOutput $soFile -RedirectStandardError $seFile
      if ($p.WaitForExit($TIMEOUT_S * 1000)) {
        $code = $p.ExitCode
        $ok = ($code -eq 0)
      } else {
        try { $p.Kill() } catch { }
        $code = 124
        $se = "TIMEOUT (> ${TIMEOUT_S}s)"
      }
      $so = Get-Content -LiteralPath $soFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
      if ($null -eq $so) { $so = "" }
      if (-not $se) {
        $se = Get-Content -LiteralPath $seFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($null -eq $se) { $se = "" }
      }
    } catch {
      $code = 1
      $se = ("{0}: {1}" -f $_.GetType().Name, $_.Message)
    } finally {
      Remove-Item -LiteralPath $soFile -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath $seFile -Force -ErrorAction SilentlyContinue
    }
  }
  if ($refused) { $nRef++ } elseif ($ok) { $nOk++ } else { $nErr++ }
  if ($so.Length -gt $MAX_CHARS) { $so = $so.Substring(0, $MAX_CHARS) + "...[truncated]" }
  if ($se.Length -gt $MAX_CHARS) { $se = $se.Substring(0, $MAX_CHARS) + "...[truncated]" }
  $outLines += ([pscustomobject]@{
    uuid = [string]$c.uuid; idx = [int]$c.idx; tool = "powershell"
    command = $cmd; ok = $ok; exit_code = $code
    stdout = $so; stderr = $se; refused = $refused
  } | ConvertTo-Json -Depth 4 -Compress)
  if ($i % 50 -eq 0) { Write-Output ("progress " + $i + "/" + $lines.Count + " " + [Math]::Round($sw.Elapsed.TotalSeconds, 1) + "s") }
}
$outLines | Out-File -LiteralPath $Out -Encoding UTF8
Write-Output ("OK=" + $nOk + " ERR=" + $nErr + " REFUSED=" + $nRef + " total=" + $lines.Count + " -> " + $Out)
