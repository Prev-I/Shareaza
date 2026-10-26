#define vcredist_name			      "Microsoft Visual C++ Redistributable"
#define vcredist_file			      "mfc140u.dll"

; v143 is the Visual Studio 2022 toolset, and its last release, 17.14, builds
; against runtime 14.44. Microsoft supports a runtime only if it is at least as
; new as the toolset, so an older runtime is replaced, not only a missing one.
; Both values can be set from the ISCC command line, which the CI uses to force
; the download path on a runner that already has the runtime.
#ifndef vcredist_min_major
  #define vcredist_min_major    14
#endif
#ifndef vcredist_min_minor
  #define vcredist_min_minor    44
#endif

; Microsoft's permalinks for the latest supported runtime. The latest is never
; older than the one a v143 build needs. Short of a preview runtime, it is not
; older than one already installed either, which a runtime installer refuses to
; downgrade.
#define vcredist32_exe          "VC_redist.x86.exe"
#define vcredist32_title        vcredist_name + " (x86)"
#define vcredist32_url          "https://aka.ms/vc14/vc_redist.x86.exe"

#define vcredist64_exe          "VC_redist.x64.exe"
#define vcredist64_title        vcredist_name + " (x64)"
#define vcredist64_url          "https://aka.ms/vc14/vc_redist.x64.exe"

#include "idp.iss"
#include "dep.iss"

[Code]
Function VCRuntimeFileIsCurrent(FileName: String): Boolean;
var
  VersionMS, VersionLS: Cardinal;
Begin
  if GetVersionNumbers( FileName, VersionMS, VersionLS ) then begin
    Result := VersionMS >= ( {#vcredist_min_major} shl 16 ) + {#vcredist_min_minor};
    Log( 'VC++ runtime: ' + FileName + ' is ' + IntToStr( VersionMS shr 16 ) + '.' + IntToStr( VersionMS and $FFFF ) + '.' + IntToStr( VersionLS shr 16 ) + '.' + IntToStr( VersionLS and $FFFF ) );
  end else begin
    Result := False;
    Log( 'VC++ runtime: ' + FileName + ' is missing' );
  end;
End;

// True when every runtime DLL Shareaza loads from Dir is there and new enough.
// Checks all three, so the log shows each version.
Function VCRuntimeIsCurrent(Dir: String): Boolean;
var
  Runtime, Cpp, Mfc: Boolean;
Begin
  Runtime := VCRuntimeFileIsCurrent( Dir + '\vcruntime140.dll' );
  Cpp := VCRuntimeFileIsCurrent( Dir + '\msvcp140.dll' );
  Mfc := VCRuntimeFileIsCurrent( Dir + '\{#vcredist_file}' );
  Result := Runtime and Cpp and Mfc;
  if Result then
    Log( 'VC++ runtime: ' + Dir + ' is current' )
  else
    Log( 'VC++ runtime: ' + Dir + ' needs {#vcredist_min_major}.{#vcredist_min_minor} or later' );
End;

Function InstallVCRedist(): Boolean;
var
  Sys64: String;
Begin
  Result := False;

  if not VCRuntimeIsCurrent( ExpandConstant( '{syswow64}' ) ) then begin
    AddProduct( '{#vcredist32_exe}', '/quiet /norestart', '{#vcredist32_title}', '{#vcredist32_url}', false, false );
    Result := True;
  end;

  // Outside 64-bit mode {sys} is redirected to the 32-bit system folder, so
  // the Win32 installer reaches the 64-bit one through {sysnative}.
  if IsWin64 then begin
    if Is64BitInstallMode then
      Sys64 := ExpandConstant( '{sys}' )
    else
      Sys64 := ExpandConstant( '{sysnative}' );
    if not VCRuntimeIsCurrent( Sys64 ) then begin
      AddProduct( '{#vcredist64_exe}', '/quiet /norestart', '{#vcredist64_title}', '{#vcredist64_url}', false, false );
      Result := True;
    end;
  end;

End;
