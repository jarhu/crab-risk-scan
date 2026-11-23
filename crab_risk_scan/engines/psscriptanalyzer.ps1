# CRAB runs this exporter with a trusted PSScriptAnalyzer installation:
#   pwsh -NoProfile -NonInteractive -File psscriptanalyzer.ps1 SOURCE_DIRECTORY REPORT_FILE [RULE,RULE,...] -ModuleManifest ABSOLUTE_MANIFEST
# The report has no script text or diagnostic messages.
param(
    [Parameter(Mandatory)][string] $SourceDirectory,
    [Parameter(Mandatory)][string] $ReportFile,
    [string] $Rules = 'PSAvoidUsingPlainTextForPassword',
    [string] $ModuleManifest
)
$ErrorActionPreference = 'Stop'
if (!$ModuleManifest -and $env:CRAB_ENGINE_DIR -and [IO.Path]::IsPathFullyQualified($env:CRAB_ENGINE_DIR)) {
    $lock = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../engines.lock.json') -Raw | ConvertFrom-Json
    $version = $lock.engines.psscriptanalyzer.version
    $ModuleManifest = Join-Path (Split-Path -Parent $env:CRAB_ENGINE_DIR) "modules/PSScriptAnalyzer/$version/PSScriptAnalyzer.psd1"
}
if (!$ModuleManifest -or ![IO.Path]::IsPathFullyQualified($ModuleManifest)) {
    throw 'Supply the absolute path to the installed PSScriptAnalyzer manifest with -ModuleManifest.'
}
Import-Module -Name $ModuleManifest -ErrorAction Stop
# Explicit settings stop Invoke-ScriptAnalyzer from loading a PSScriptAnalyzerSettings.psd1 found in the target.
$settings = @{ IncludeRules = [string[]]@($Rules -split ',' | Where-Object { $_ }) }
$records = @(Invoke-ScriptAnalyzer -Path $SourceDirectory -Recurse -Settings $settings | ForEach-Object {
    [ordered]@{
        RuleName = $_.RuleName
        ScriptPath = $_.ScriptPath
        Severity = $_.Severity.ToString()
        Extent = [ordered]@{
            StartLineNumber = $_.Extent.StartLineNumber
            EndLineNumber = $_.Extent.EndLineNumber
            StartColumnNumber = $_.Extent.StartColumnNumber
            EndColumnNumber = $_.Extent.EndColumnNumber
        }
    }
})
$json = ConvertTo-Json -InputObject $records -Depth 4
[IO.File]::WriteAllText($ReportFile, $json, [Text.UTF8Encoding]::new($false))
