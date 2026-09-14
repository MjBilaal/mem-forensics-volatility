# Wrapper cincan/volatility (PowerShell) — TP CDSI M1
# Usage : .\vol.ps1 -f /data/memdump.raw <plugin> [options]

param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $args)

$image   = if ($env:VOL_IMAGE) { $env:VOL_IMAGE } else { "cincan/volatility:latest" }
$workdir = (Get-Location).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker est requis."
    exit 1
}

docker run --rm `
    -v "${workdir}:/data" `
    -w /data `
    --read-only `
    --tmpfs /tmp:rw,size=512m `
    $image @args
