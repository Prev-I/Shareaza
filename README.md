# Shareaza, Prev-I fork

Shareaza is a peer-to-peer client for Windows that downloads from Gnutella2, Gnutella, eDonkey2000,
BitTorrent and HTTP sources. This is a personal fork. It builds Shareaza's Windows installers on
GitHub Actions and carries the fixes from a static security audit of the code added after the
original project ended ([docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md)). It also serves as a
reference client for testing GWebCaches ([docs/ORACLE.md](docs/ORACLE.md)).

## Download and verify

This is an unofficial personal fork. It is not the original Shareaza project, and the original
project's authors have nothing to do with it.

The [Releases](https://github.com/Prev-I/Shareaza/releases) page is the only place this fork
publishes installers. Do not trust an installer from anywhere else. The installers need Windows 10
or later.

Each release from previ.8 on lists these checks. For older releases only the `Get-FileHash`
check applies, against their `SHA256SUMS.txt`, where the release has one. Run any of them on a
download:

- Built by this repository's release workflow:
  `gh attestation verify <file> --repo Prev-I/Shareaza --signer-workflow Prev-I/Shareaza/.github/workflows/release.yml`
- Unchanged since publication:
  `gh release verify-asset <tag> <file> --repo Prev-I/Shareaza`
- Without `gh`: `Get-FileHash <file> -Algorithm SHA256`, compared with `SHA256SUMS.txt` or the
  sha256 GitHub shows beside each file.

The `gh` checks need `gh` 2.81.0 or later. The release process and the file contract are in
[docs/RELEASING.md](docs/RELEASING.md). To report a security problem, see
[SECURITY.md](SECURITY.md).

## History and credits

This fork stands on the work of others:

- **The original Shareaza project** on SourceForge, with its source in Subversion:
  [sourceforge.net/p/shareaza/code](https://sourceforge.net/p/shareaza/code/), trunk at
  `https://svn.code.sf.net/p/shareaza/code/trunk`. Its site, wiki and forum are at
  [shareaza.sourceforge.net](https://shareaza.sourceforge.net/), and the Help menu still points
  there.
- **ivan386**, who imported SVN build 9329 to Git in 2013 and kept it going:
  [github.com/ivan386/Shareaza](https://github.com/ivan386/Shareaza).
- **ansani**, who continued it as 2.7.10.x with a Visual Studio 2022 build, HTTPS downloads and
  GitHub releases: [github.com/ansani/Shareaza](https://github.com/ansani/Shareaza). This
  repository is a fork of ansani's; its `master` branch is that code as imported.

## Building

The reference setup is the release workflow, [.github/workflows/release.yml](.github/workflows/release.yml),
which builds both installers on a `windows-2022` runner. To build by hand you need:

- **Visual Studio 2022** with the *Desktop development with C++* workload, including the **v143**
  toolset and its **ATL** and **MFC** libraries. GitHub's newer runner images (`windows-latest`,
  `windows-2025`) ship the v143 compiler without v143 ATL and MFC, and cannot build this solution.
- **Inno Setup 6**, version 6.3 or later, installed in its default folder,
  `C:\Program Files (x86)\Inno Setup 6`: the installer project calls `ISCC.exe` by that path.
  CI uses 6.7.3; Inno Setup 7 would need a project change.
- **NuGet**, to restore the packages the solution uses.

Then, from a Developer Command Prompt for VS 2022:

```bat
nuget restore vc143\Shareaza.sln
set CL=/D_SILENCE_STDEXT_ARR_ITERS_DEPRECATION_WARNING /DRELEASE_BUILD=1
msbuild vc143\Shareaza.sln /t:Rebuild /p:Configuration=Release /p:Platform=x64
```

- `CL` is added to every compile. Its first define silences a Visual Studio 17.8+ deprecation that
  the project's SDL checks would turn into an error.
- `RELEASE_BUILD=1` marks the build as a release. Without it the client is an alpha build: it shows
  an alpha-test warning at every start, and from seven days after it was compiled also a message
  that the test period has ended. CI defines it the same way. `vc143\ReleaseBuild.props` is not
  used: it also imports `WindowsXP.props`, which targets Windows XP for the 32-bit build.
- Use `/p:Platform=Win32` for the 32-bit build, and `Debug` for a debug build.
- Opening `vc143\Shareaza.sln` in Visual Studio works too; set `CL` the same way first, in the
  environment Visual Studio starts from, or you get an alpha build.
- The installer lands in `setup\builds`.

Building x64 on 32-bit Windows fails while registering the 64-bit DLLs, and you could not test the
result there anyway.

### No longer needed

Older instructions asked for more, and none of it is needed now:

- **gzip.exe:** files are compressed by [7z.cmd](7z.cmd), with the compression built into Windows
  PowerShell.
- **The DirectX SDK (August 2007):** the one header still used from it, a trimmed `qedit.h`, is in
  the repository (`plugins/MediaImageServices` and `plugins/MediaLibraryBuilder`).
- **The "Unicode Inno Setup QuickStart Pack":** Inno Setup 6 is Unicode-only.
