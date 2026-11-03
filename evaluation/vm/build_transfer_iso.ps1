# Build the read-only transfer ISO for the offline evaluation VM (Windows host, PowerShell 5.1+).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File evaluation\vm\build_transfer_iso.ps1 `
#       -Samples C:\tmp\fm-study\samples -Acquired C:\tmp\fm-study\acquired -OutDir C:\tmp\fm-study
#
# Contents: the exact committed source (git bundle of the branch + git archive of the commit),
# COMMIT.txt, the benign samples and their manifest, the verified Didier Stevens tools with their
# provenance, install_from_iso.sh taken from the commit itself, and SHA256SUMS over everything.
# Refuses uncommitted changes, EICAR material, and samples that do not match their manifest.
# The image is UDF (mount -t udf in the guest); an optical medium is read-only by nature.
param(
    [Parameter(Mandatory = $true)][string]$Samples,
    [Parameter(Mandatory = $true)][string]$Acquired,
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$Branch = "security/malware-research-hardening"
)
$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# The executable, never a function or alias of the same name (a function called "Git" that runs
# "& git" would call itself: PowerShell resolves names case-insensitively, functions first).
$gitExe = (Get-Command git -CommandType Application | Select-Object -First 1).Source
function Invoke-Git { & $gitExe -C $repo -c core.autocrlf=false @args; if ($LASTEXITCODE -ne 0) { throw "git $args failed" } }

$commit = (Invoke-Git rev-parse HEAD).Trim()
if ((Invoke-Git rev-parse "refs/heads/$Branch").Trim() -ne $commit) { throw "HEAD is not the tip of $Branch" }
if (Invoke-Git status --porcelain) { throw "the working tree has uncommitted changes; the ISO must hold exactly one commit" }
if ((Invoke-Git rev-parse "refs/remotes/origin/$Branch").Trim() -ne $commit) { throw "$commit is not pushed to origin/$Branch" }

# Refuse EICAR and anything else that is not part of this transfer.
foreach ($dir in @($Samples, $Acquired)) {
    if (Get-ChildItem -Recurse -Force $dir | Where-Object { $_.Name -match "eicar" }) { throw "EICAR material found in $dir" }
}
$allowedTools = @("ds-pdfid", "ds-mpdf", "ds-make-pdf-javascript", "ds-make-pdf-embedded")
foreach ($d in Get-ChildItem -Directory $Acquired) { if ($allowedTools -notcontains $d.Name) { throw "unexpected tool directory $($d.Name)" } }

# Every sample must match the manifest before it is packaged.
$rows = Import-Csv (Join-Path $Samples "manifest.csv")
if ($rows.Count -ne 13) { throw "expected the 13 approved samples, found $($rows.Count)" }
foreach ($r in $rows) {
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $Samples $r.path)).Hash.ToLower()
    if ($actual -ne $r.sha256) { throw "$($r.sample_id): file does not match the manifest" }
}

$short = $commit.Substring(0, 7)
$stage = Join-Path $env:TEMP "fm-eval-iso-$short"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory $stage | Out-Null

Invoke-Git bundle create (Join-Path $stage "filesmagic.bundle") "refs/heads/$Branch" | Out-Null
Invoke-Git archive --format=tar --prefix=filesmagic-security-engine/ -o (Join-Path $stage "source-$short.tar") $commit
Invoke-Git archive --format=zip -o (Join-Path $stage "script.zip") $commit evaluation/vm/install_from_iso.sh
Expand-Archive (Join-Path $stage "script.zip") $stage
Move-Item (Join-Path $stage "evaluation\vm\install_from_iso.sh") (Join-Path $stage "install_from_iso.sh")
Remove-Item -Recurse -Force (Join-Path $stage "evaluation"), (Join-Path $stage "script.zip")
Copy-Item -Recurse $Samples (Join-Path $stage "samples")
Copy-Item -Recurse $Acquired (Join-Path $stage "acquired")
[IO.File]::WriteAllText((Join-Path $stage "COMMIT.txt"), "$commit`n")
[IO.File]::WriteAllText((Join-Path $stage "BRANCH.txt"), "$Branch`n")
[IO.File]::WriteAllText((Join-Path $stage "README.txt"), @"
FilesMagic evaluation transfer medium (read-only). Commit $commit on $Branch.
Contains: the commit (filesmagic.bundle, source-$short.tar), 13 benign samples with manifest.csv,
the verified Didier Stevens tools with provenance.json, install_from_iso.sh, SHA256SUMS.
No EICAR, no third-party sample documents, no executables.
In the VM: bash <mount point>/install_from_iso.sh  (see docs/eicar-didier-evaluation.md)
"@.Replace("`r`n", "`n"))

$lines = Get-ChildItem -Recurse -File $stage | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($stage.Length + 1).Replace("\", "/")
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $rel
}
[IO.File]::WriteAllText((Join-Path $stage "SHA256SUMS"), (($lines -join "`n") + "`n"))

# UDF image through the Windows imaging API (IMAPI2FS).
Add-Type -TypeDefinition @"
using System; using System.IO; using System.Runtime.InteropServices; using System.Runtime.InteropServices.ComTypes;
public static class FmIsoWriter {
    public static void Save(object image, string path, int blockSize, long blocks) {
        IStream s = (IStream)image; byte[] buf = new byte[blockSize]; IntPtr read = Marshal.AllocHGlobal(4);
        try { using (FileStream f = File.Create(path)) { for (long n = 0; n < blocks; n++) { s.Read(buf, blockSize, read); f.Write(buf, 0, Marshal.ReadInt32(read)); } } }
        finally { Marshal.FreeHGlobal(read); }
    }
}
"@
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 4  # UDF: long file names and exact bytes
$fsi.VolumeName = "FM_EVAL_$short"
$fsi.Root.AddTree($stage, $false)
$result = $fsi.CreateResultImage()
$iso = Join-Path $OutDir "fm-eval-$short.iso"
if (Test-Path $iso) { throw "$iso already exists" }
[FmIsoWriter]::Save($result.ImageStream, $iso, $result.BlockSize, $result.TotalBlocks)

$isoHash = (Get-FileHash -Algorithm SHA256 $iso).Hash.ToLower()
[IO.File]::WriteAllText("$iso.sha256", "$isoHash  $(Split-Path -Leaf $iso)`n")
Write-Output "ISO      $iso"
Write-Output "SHA-256  $isoHash"
Write-Output "commit   $commit"
Write-Output "files    $($lines.Count) (listed in SHA256SUMS on the medium)"
Remove-Item -Recurse -Force $stage
