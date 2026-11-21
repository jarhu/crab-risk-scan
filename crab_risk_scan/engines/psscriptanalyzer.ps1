# CRAB runs this exporter with a trusted PSScriptAnalyzer installation:
#   pwsh -NoProfile -NonInteractive -File psscriptanalyzer.ps1 SOURCE_DIRECTORY REPORT_FILE [RULE,RULE,...]
# The report has no script text or diagnostic messages.
param(
    [Parameter(Mandatory)][string] $SourceDirectory,
    [Parameter(Mandatory)][string] $ReportFile,
    [string] $Rules = 'PSAvoidUsingPlainTextForPassword'
)
$ErrorActionPreference = 'Stop'
Import-Module PSScriptAnalyzer
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
