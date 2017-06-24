
$Version = "1.0.0.5"
$NewVersion = 'AssemblyVersion("' + $Version + '")';
$NewFileVersion = 'AssemblyFileVersion("' + $Version + '")';

$files = Get-ChildItem . -Include 'AssemblyInfo.cs' -Recurse
$files | ForEach-Object{
    Write-Host ('Change version in file: {0}' -f $_.FullName )

    $content = Get-Content -Path $_.FullName -Encoding UTF8
    
    $content = $content -replace 'AssemblyVersion\("[0-9]+(\.([0-9]+|\*)){1,3}"\)', $NewVersion
    $content = $content -replace 'AssemblyFileVersion\("[0-9]+(\.([0-9]+|\*)){1,3}"\)', $NewFileVersion

    Set-Content -Path $_.FullName -Value $content -Encoding UTF8
}