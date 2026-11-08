param(
    [ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [ValidateSet('Release', 'Debug')][string]$Configuration = 'Release',
    [string]$CompilerRoot = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildDirectory = Join-Path $projectRoot "build/$Architecture-$Configuration"
$outputDirectory = Join-Path $projectRoot "dist/$Architecture"
$cmakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
if (!$cmakeCommand) { throw 'CMake 3.20 or later is required.' }

# Prefer an explicitly supplied MinGW directory, then PATH and common locations.
$compilerCandidates = @()
if ($CompilerRoot) {
    $compilerCandidates += (Join-Path $CompilerRoot 'bin/gcc.exe')
    $compilerCandidates += (Join-Path $CompilerRoot 'gcc.exe')
} else {
    $pathCompiler = Get-Command gcc -ErrorAction SilentlyContinue
    if ($pathCompiler) { $compilerCandidates += $pathCompiler.Source }
    $folder = if ($Architecture -eq 'x64') { 'mingw64' } else { 'mingw32' }
    foreach ($drive in @('C:', 'D:')) {
        $compilerCandidates += "$drive/Program Files/$folder/bin/gcc.exe"
        $compilerCandidates += "$drive/$folder/bin/gcc.exe"
        $compilerCandidates += "$drive/msys64/$folder/bin/gcc.exe"
    }
}
$compiler = $null
foreach ($candidate in $compilerCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        $targetTriple = & $candidate -dumpmachine
        if ($LASTEXITCODE -ne 0) { continue }
        if (($Architecture -eq 'x64' -and $targetTriple -match '^x86_64') -or
            ($Architecture -eq 'x86' -and $targetTriple -match '^i[3-6]86')) {
            $compiler = [IO.Path]::GetFullPath($candidate)
            break
        }
    }
}
$previousPath = $env:PATH
try {
    if ($compiler) {
        $compilerDirectory = Split-Path $compiler
        $env:PATH = "$compilerDirectory;$previousPath"
        $resourceCompiler = (Join-Path $compilerDirectory 'windres.exe').Replace([char]92, [char]47)
        $compiler = $compiler.Replace([char]92, [char]47)
        if (!(Test-Path -LiteralPath $resourceCompiler)) { throw 'windres.exe is missing.' }
        $generator = if (Get-Command ninja -ErrorAction SilentlyContinue) { 'Ninja' } else { 'MinGW Makefiles' }
        $configureArguments = @('-S', $projectRoot, '-B', $buildDirectory, '-G', $generator,
            "-DCMAKE_BUILD_TYPE=$Configuration", "-DCMAKE_C_COMPILER=$compiler",
            "-DCMAKE_RC_COMPILER=$resourceCompiler")
        & $cmakeCommand.Source @configureArguments
    } else {
        if ($CompilerRoot) { throw "No matching $Architecture GCC compiler found in $CompilerRoot." }
        $platform = if ($Architecture -eq 'x64') { 'x64' } else { 'Win32' }
        & $cmakeCommand.Source -S $projectRoot -B $buildDirectory -A $platform
    }
    if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed.' }
    & $cmakeCommand.Source --build $buildDirectory --config $Configuration --parallel
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }
    $executable = Join-Path $buildDirectory 'CredentialUI.exe'
    if (!(Test-Path -LiteralPath $executable)) {
        $executable = Join-Path $buildDirectory "$Configuration/CredentialUI.exe"
    }
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
    $outputFile = Join-Path $outputDirectory 'CredentialUI.exe'
    Copy-Item -LiteralPath $executable -Destination $outputFile -Force
    Write-Host "Built: $outputFile"
    # Remove only known obsolete deliverables from this architecture's dist.
    foreach ($name in @('CredentialUIHost.exe', 'CredentialUIInjector.exe', 'CredentialUIBridge.dll')) {
        $obsolete = Join-Path $outputDirectory $name
        if (Test-Path -LiteralPath $obsolete) {
            Remove-Item -LiteralPath $obsolete -Force
        }
    }

} finally {
    $env:PATH = $previousPath
}
