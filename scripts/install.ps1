<#
.SYNOPSIS
  Installs Kukux Sign Agent on Windows (docs/installation.md).

.DESCRIPTION
  irm https://github.com/kukux/digital-signature-agent/releases/latest/download/install.ps1 | iex

  With options:
  & ([scriptblock]::Create((irm https://github.com/kukux/digital-signature-agent/releases/latest/download/install.ps1))) -Version 1.2.0

  From a downloaded installer:
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -From .\kukux-sign-agent-1.2.0-win-x64.exe

  Before running anything it checks that:
    1. the installer's SHA-512 matches latest.yml from the same release;
    2. the installer has a valid Authenticode signature from the expected publisher.
  It installs per user (no administrator rights), registers kukuxsign:// and starts the agent.
#>
[CmdletBinding()]
param(
  [string]$Version = $env:KUKUX_AGENT_VERSION,
  [string]$BaseUrl = $env:KUKUX_AGENT_BASE_URL,
  [string]$From,
  [switch]$AllowUnsigned,
  [switch]$NoLaunch,
  [switch]$Uninstall,
  [switch]$Purge
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Invoke-WebRequest is much faster without the progress bar

$AppName = 'Kukux Sign Agent'
$Scheme = 'kukuxsign'
$DefaultReleases = 'https://github.com/kukux/digital-signature-agent/releases'
# Pinned by the release workflow; override with KUKUX_AGENT_PUBLISHER.
$ExpectedPublisher = if ($env:KUKUX_AGENT_PUBLISHER) { $env:KUKUX_AGENT_PUBLISHER } else { '__KUKUX_PUBLISHER__' }
$AllowUnsignedBuild = $AllowUnsigned.IsPresent -or $env:KUKUX_AGENT_ALLOW_UNSIGNED -eq '1'

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Stop-Install([string]$Message) { throw "Kukux Sign Agent install failed: $Message" }

function Get-InstalledAgent {
  # electron-builder's per-user NSIS installer registers here; DisplayIcon is "<exe>,0".
  $keys = Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue
  foreach ($key in $keys) {
    $props = Get-ItemProperty $key.PSPath
    if ($props.DisplayName -like "$AppName*") {
      $exe = ($props.DisplayIcon -replace ',\d+$', '').Trim('"')
      return [pscustomobject]@{
        Exe       = $exe
        Version   = $props.DisplayVersion
        Uninstall = $props.QuietUninstallString, $props.UninstallString | Where-Object { $_ } | Select-Object -First 1
      }
    }
  }
  return $null
}

function Stop-Agent {
  $running = Get-Process -Name $AppName -ErrorAction SilentlyContinue
  if ($running) {
    Write-Step 'Closing the running agent'
    $running | Stop-Process -Force
    Start-Sleep -Milliseconds 800
  }
}

function Invoke-Download([string]$Url, [string]$OutFile) {
  $uri = [Uri]$Url
  $local = $uri.Host -in @('localhost', '127.0.0.1')
  if ($uri.Scheme -ne 'https' -and -not ($uri.Scheme -eq 'http' -and $local)) {
    Stop-Install "refusing to download over $($uri.Scheme): $Url"
  }
  try {
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -MaximumRedirection 5
  } catch {
    Stop-Install "download failed: $Url ($($_.Exception.Message))"
  }
}

# electron-builder metadata: "files:" entries of "- url:" followed by "sha512:".
function Find-ReleaseFile([string]$YamlPath, [string]$Suffix) {
  $url = $null
  foreach ($line in Get-Content $YamlPath) {
    if ($line -match '^\s*-\s*url:\s*(.+?)\s*$') { $url = $Matches[1].Trim("'", '"'); continue }
    if ($url -and $line -match '^\s+sha512:\s*(.+?)\s*$') {
      if ($url.EndsWith($Suffix)) { return [pscustomobject]@{ Url = $url; Sha512 = $Matches[1].Trim("'", '"') } }
      $url = $null
    }
  }
  return $null
}

function Get-Sha512Base64([string]$Path) {
  $hex = (Get-FileHash -Algorithm SHA512 -Path $Path).Hash
  $bytes = [byte[]]::new($hex.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
  return [Convert]::ToBase64String($bytes)
}

function Test-InstallerSignature([string]$Path) {
  if ($AllowUnsignedBuild) {
    Write-Warning 'Skipping the signature check (-AllowUnsigned). Only do this for your own builds.'
    return
  }
  Write-Step 'Verifying signature'
  $sig = Get-AuthenticodeSignature -FilePath $Path
  if ($sig.Status -ne 'Valid') { Stop-Install "the installer's signature is $($sig.Status): $($sig.StatusMessage)" }
  # Still the "__…__" placeholder means the release didn't pin a publisher.
  if ($ExpectedPublisher -notlike '__*__') {
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notmatch ('(^|,\s*)(CN|O)=\"?' + [Regex]::Escape($ExpectedPublisher) + '\"?(,|$)')) {
      Stop-Install "signed by '$subject', expected $ExpectedPublisher"
    }
  }
  Write-Host "    signed by $($sig.SignerCertificate.Subject)" -ForegroundColor DarkGray
}

function Register-Scheme([string]$Exe) {
  # The agent also does this on start (app.setAsDefaultProtocolClient); doing it
  # here makes links work before the first launch.
  $root = "HKCU:\Software\Classes\$Scheme"
  New-Item -Path "$root\shell\open\command" -Force | Out-Null
  Set-ItemProperty -Path $root -Name '(Default)' -Value 'URL:Kukux Sign'
  Set-ItemProperty -Path $root -Name 'URL Protocol' -Value ''
  Set-ItemProperty -Path "$root\shell\open\command" -Name '(Default)' -Value "`"$Exe`" `"%1`""
}

function Uninstall-Agent {
  Stop-Agent
  $agent = Get-InstalledAgent
  if ($agent -and $agent.Uninstall) {
    Write-Step "Uninstalling $AppName $($agent.Version)"
    $command = $agent.Uninstall
    if ($command -notmatch '/S\b') { $command = "$command /S" }
    # The extra quotes stop cmd from stripping the ones around the exe path.
    Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$command`"" -Wait -WindowStyle Hidden
    # NSIS uninstallers relaunch themselves from %TEMP%, so -Wait returns early.
    for ($i = 0; $i -lt 60 -and (Get-InstalledAgent); $i++) { Start-Sleep -Milliseconds 500 }
    if (Get-InstalledAgent) { Write-Warning 'The uninstaller is still running; it will finish in the background.' }
  } else {
    Write-Host "$AppName is not installed."
  }
  Remove-Item -Path "HKCU:\Software\Classes\$Scheme" -Recurse -Force -ErrorAction SilentlyContinue
  if ($Purge) {
    Remove-Item -Path (Join-Path $env:APPDATA $AppName) -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $env:LOCALAPPDATA "$AppName-updater") -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Removed settings and paired-app list.'
  }
  Write-Host ''
  Write-Host 'If this computer was paired, revoke it in the web app under My signing devices.'
}

function Install-Agent {
  if (-not [Environment]::Is64BitOperatingSystem) { Stop-Install 'a 64-bit Windows is required' }
  $build = [Environment]::OSVersion.Version.Build
  if ($build -lt 19045) { Write-Warning "Windows 10 22H2 (build 19045) or newer is supported; this PC is build $build." }
  if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Write-Host 'Windows on ARM: installing the x64 build (runs under emulation).' }

  # PowerShell 5.1 may default to TLS 1.0.
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("kukux-agent-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    if ($From) {
      $installer = (Resolve-Path $From).Path
      Write-Step "Installing from $installer"
    } else {
      $base = $BaseUrl
      if (-not $base) {
        $base = if ($Version) { "$DefaultReleases/download/v$($Version.TrimStart('v'))" } else { "$DefaultReleases/latest/download" }
      }
      $base = $base.TrimEnd('/')

      Write-Step "Checking $base"
      $yaml = Join-Path $tmp 'latest.yml'
      Invoke-Download "$base/latest.yml" $yaml
      $release = (Select-String -Path $yaml -Pattern '^version:\s*(.+)$' | Select-Object -First 1).Matches.Groups[1].Value.Trim("'", '"', ' ')
      if ($Version -and $Version.TrimStart('v') -ne $release) { Stop-Install "asked for $Version but the release metadata is for $release" }

      $file = Find-ReleaseFile $yaml '-win-x64.exe'
      if (-not $file) { Stop-Install 'the release has no Windows x64 installer' }

      Write-Step "Downloading $AppName $release"
      $installer = Join-Path $tmp ([IO.Path]::GetFileName($file.Url))
      Invoke-Download "$base/$($file.Url)" $installer
      if ((Get-Sha512Base64 $installer) -ne $file.Sha512) {
        Stop-Install "SHA-512 mismatch for $($file.Url): the download is corrupt or was tampered with"
      }
      Write-Host '    SHA-512 verified' -ForegroundColor DarkGray
    }

    Test-InstallerSignature $installer
    Stop-Agent

    Write-Step 'Installing (per user, no administrator rights needed)'
    $process = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
    if ($process.ExitCode -ne 0) { Stop-Install "the installer exited with code $($process.ExitCode)" }

    $agent = Get-InstalledAgent
    if (-not $agent -or -not (Test-Path $agent.Exe)) { Stop-Install 'the installer finished but the agent was not found' }
    Register-Scheme $agent.Exe
    Write-Host "Installed $AppName $($agent.Version) to $(Split-Path $agent.Exe)" -ForegroundColor Green

    if (-not $NoLaunch) {
      Start-Process -FilePath $agent.Exe
      Write-Host 'It runs in the notification area (look for the key icon).'
    }
    Write-Host ''
    Write-Host 'Next: in the web app, open My signing devices > Pair desktop agent,'
    Write-Host 'then enter the address and code it shows in the agent.'
  } finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if ($Uninstall) { Uninstall-Agent } else { Install-Agent }
