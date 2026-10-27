@echo off
setlocal

rem Usage: 7z.cmd <input file> <output .gz file>
rem Compresses the input into a gzip file with .NET's GZipStream (Windows PowerShell),
rem so the build needs no external archiver. Exits non-zero, and leaves no output, on error.

set "GZ_SRC=%~1"
set "GZ_DST=%~2"

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop';" ^
  "try {" ^
  "  $in = [IO.File]::OpenRead($env:GZ_SRC);" ^
  "  try {" ^
  "    $out = [IO.File]::Create($env:GZ_DST);" ^
  "    try {" ^
  "      $gz = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionLevel]::Optimal);" ^
  "      try { $in.CopyTo($gz) } finally { $gz.Dispose() }" ^
  "    } finally { $out.Dispose() }" ^
  "  } finally { $in.Dispose() };" ^
  "  exit 0" ^
  "} catch {" ^
  "  [Console]::Error.WriteLine('7z.cmd: ' + $env:GZ_DST + ': ' + $_.Exception.Message);" ^
  "  if (Test-Path -LiteralPath $env:GZ_DST) { Remove-Item -LiteralPath $env:GZ_DST -Force -ErrorAction SilentlyContinue };" ^
  "  exit 1" ^
  "}"
exit /b %errorlevel%
