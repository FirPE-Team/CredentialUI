param(
    [ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [string]$CompilerRoot = ''
)
& (Join-Path $PSScriptRoot 'scripts/build.ps1') @PSBoundParameters
