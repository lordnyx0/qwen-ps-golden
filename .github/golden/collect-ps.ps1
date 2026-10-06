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
    # Job + filho powershell com redirect: exit via $LASTEXITCODE (Start-Process .ExitCode
    # volta nulo no Windows PowerShell 5.1). Timeout via Wait-Job.
    $soFile = [System.IO.Path]::GetTempFileName()
    $seFile = [System.IO.Path]::GetTempFileName()
    $job = $null
    try {
      $job = Start-Job -ScriptBlock {
        param($c, $so, $se)
        & powershell -NoProfile -NonInteractive -Command $c > $so 2> $se
        return $LASTEXITCODE
      } -ArgumentList $cmd, $soFile, $seFile
      $done = Wait-Job -Job $job -Timeout $TIMEOUT_S
      if ($done) {
        $rawCode = Receive-Job -Job $job
        # Receive-Job as vezes devolve PSObject embrulhado ({value, PSComputerName...}): normaliza.
        if ($rawCode -is [int]) { $code = $rawCode }
        elseif ($null -ne $rawCode.value) { $code = [int]$rawCode.value }
        elseif ($null -eq $rawCode) { $code = 1 } else { $code = 1 }
        $ok = ($code -eq 0)
      } else {
        $code = 124
        $se = "TIMEOUT (> ${TIMEOUT_S}s)"
      }
      $soRaw = Get-Content -LiteralPath $soFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
      # Get-Content as vezes devolve objeto embrulhado ({value, PSPath...}): normaliza p/ texto.
      if ($soRaw -is [string]) { $so = $soRaw }
      elseif ($null -ne $soRaw.value) { $so = [string]$soRaw.value } else { $so = "" }
      if (-not $se) {
        $seRaw = Get-Content -LiteralPath $seFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
        if ($seRaw -is [string]) { $se = $seRaw }
        elseif ($null -ne $seRaw.value) { $se = [string]$seRaw.value } else { $se = "" }
      }
    } catch {
      $code = 1
      $se = ("{0}: {1}" -f $_.GetType().Name, $_.Message)
    } finally {
      if ($null -ne $job) { Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
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
