# Local diagnostics

How to turn on the client's local crash and hang diagnostics, where the files go, and how to read a
dump. Nothing is sent anywhere: every file stays on the computer until the user moves or deletes it.

The diagnostics are off by default. With them on, the client writes a minidump when it crashes, and a
watchdog writes one when the network side stops making progress, for example one core pinned at 100%
while the window still answers. The dump says where every thread was at that moment.

The crash filter never sees `abort`, `/GS` failures and other fast-fail calls, the CRT invalid-parameter
and pure-call handlers, or anything while a debugger is attached. For those, fall back to "Taking a
dump by hand" below.

## Turning diagnostics on

Both settings are under Tools → Settings → Advanced:

| Setting | Default | Meaning |
|---|---|---|
| `General.Diagnostics` | off | Writes a dump on a crash, and runs the watchdog. |
| `General.DiagnosticsHangSeconds` | 30 | How long the client may make no progress before the watchdog writes a hang dump. From 10 to 600. |

The settings are read once, when the client starts. A change takes effect at the next start.

A crash before the settings are loaded, or in the last steps of shutdown, is not covered.

## Where files go

Everything is in `<UserPath>\Data\Diagnostics\`. `<UserPath>` is `%APPDATA%\Shareaza` unless the
installation was set up with another user path.

- Dumps are named `<YYYYMMDD-HHMMSS>-<crash|hang>-<version>.dmp`, with the time in UTC, for example
  `20261120-153012-hang-2.7.11.4.dmp`.
- At most 5 dumps are kept, crash and hang dumps together. When a new one is written, the oldest are
  deleted.
- `Diagnostics.log` is the watchdog's own log. At 1 MB it is renamed to `Diagnostics.old.log` and a
  new one is started.

A dump holds the stacks of all threads and part of the program's memory. It can contain peer
addresses, search terms, and the names and paths of files the client has open (downloads, shared
files). Look at a dump before sending it to anyone, and send it only to someone you trust with that.

The folder is user data like the rest of `Data\`. The uninstaller deletes the `Data` folder in the
installation folder and `%APPDATA%\Shareaza\Data`, so the dumps go with it when the user path is
the default (`%APPDATA%\Shareaza`) or the installation folder. With any other user path they stay
until you delete them. To remove them earlier, delete the files in the folder.

## Taking a dump by hand

A dump by hand needs no setting, and works in any release. Use it when the program hangs and no hang
dump was written, for example because the diagnostics were off.

- Task Manager: Details tab, right-click `Shareaza.exe`, Create dump file. Task Manager shows where
  the file is saved. The dump is full, so it is large.
- ProcDump from Sysinternals: `procdump -ma Shareaza.exe`, or `procdump -ma <pid>`. It writes a full
  dump into the current folder.

Take the dump while the problem is happening.

## Opening a dump

From previ.9 on, each release has a symbols archive for each platform, beside the installer:
`iShareaza_<version>_<Win32|x64>_symbols_<YYYY-MM-DD>.zip`. It holds the PDB files of the
`Shareaza.exe` and of the plugins and libraries the installer ships, built together with the
installer, so only that release's PDBs match its dump. Take the archive for the same platform and
version as the dump.

1. Extract the archive into a folder.
2. Open the dump in WinDbg or in Visual Studio (File → Open → File).
3. Set the symbol path to the extracted folder and Microsoft's symbol server. In WinDbg that is
   File → Settings → Debugging settings → Symbol path, or `.sympath`:

   ```text
   <extracted zip>;srv*<cache>*https://msdl.microsoft.com/download/symbols
   ```

   `<cache>` is a local folder for downloaded symbols, such as `C:\symbols`. In Visual Studio, the
   same two entries go in Tools → Options → Debugging → Symbols.
4. In WinDbg run `.reload`, then `~*k` to list the stack of every thread. A hang shows as a thread
   that sits in the same place in every dump, often waiting for a lock that another thread holds.

In Visual Studio, Debug with Native Only opens the same stacks in the Threads and Call Stack windows.

To check that a PDB belongs to the program that was running, WinDbg's `lm` command lists each module
and whether its symbols were loaded; a mismatch is shown as export symbols only.
