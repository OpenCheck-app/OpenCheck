# OpenCheck

OpenCheck is an open-source, read-only Windows app that checks a PC for Roblox executors, externals, unfair FastFlags, FastFlag tools, macros and lag switches, including ones that were already deleted. It needs no install and never connects to the internet.

**Not affiliated with Roblox Corporation.**

**Official download:** this repository's [Releases](../../releases) page only. OpenCheck never asks you to turn off your antivirus or add an exclusion. If a copy does, it's fake.

## For the person being checked

**What it looks at**
- File and folder **names** in your user folders, ProgramData and Program Files. File contents are never opened, with four exceptions: a file that already matched the cheat list gets a fingerprint (SHA-256), Roblox FastFlag files are read for flags, Roblox's own logs are read for game join times, and Roblox script files (.lua/.luau, and .txt inside an executor's folders) are read for executor-only functions like getgenv or hookfunction. Only the names of those functions are reported, never the script.
- Windows' records of programs that ran or were on the PC: Prefetch, BAM, UserAssist, MuiCache, Compatibility Assistant, the compatibility cache (ShimCache, which keeps program paths for months, even after they're deleted) and Recent files.
- Records cleaners usually miss: the Program Compatibility Assistant launch log, Windows Defender's own support log, Windows crash reports (including which files were loaded inside Roblox when it crashed), and drivers installed in the last 90 days.
- Deleted files: the Recycle Bin and the drive's change log (NTFS USN journal), read newest first so recent deletions are always covered, filtered to cheat names only.
- Windows Security (Defender) detections and antivirus exclusions.
- Cleared event logs, logs that are suspiciously short, clock changes, and wiped Prefetch, Roblox logs or recent-file history.
- The Run box (Win+R) and Explorer address bar history, recent website lookups (DNS cache), Windows Security's current settings, and USB devices used to flash DMA cards. Lookups and typed commands are only compared to the cheat list; nothing else is kept.
- PowerShell history, checked only for commands that wipe the records above (like `fsutil usn deletejournal` or deleting Prefetch). Only those matching lines are kept.
- When Windows was last reset or installed, and when the Windows account was created (a reset in the last week is flagged for review).
- Windows Firewall rules that block Roblox (a common lag-switch trick), and the firewall's own history of Roblox rules being added and removed, which is how lag-switch macros work.
- Lag switches and VPNs: lag tools installed as drivers or services (WinDivert, NetLimiter and others), VPN and game ping-booster adapters (connected or just installed), and short internet drops that happened while a Roblox game was open. A physical switch on the cable or a macro that turns the network off shows up as these drops. Only adapter names and connect/disconnect times are read, and nothing is sent anywhere.
- Roblox's own log files, to list recent games (place ID, join and leave times only) and show which game was open when a cheat ran. Nothing else from the logs is kept, and server addresses are ignored.
- FastFlag files from Roblox and every bootstrapper (Bloxstrap, Fishstrap, Voidstrap, Froststrap and others), plus FastFlag list files in Desktop, Downloads and Documents. Bootstrappers are listed as context only and never count against anyone.
- Macros and auto clickers (AutoHotkey, TinyTask, OP/GS Auto Clicker...) and lag-switch tools (Clumsy, NetLimiter, NetBalancer, WinDivert).
- Whether the PC is a virtual machine, whether VM software or Android emulators are installed or were used, and PCIe devices that could be DMA cards.
- Programs running right now.
- USB drives plugged in during the last 30 days, programs run from USB or external drives, and sandbox or "freeze" tools (Sandboxie, Deep Freeze, Shadow Defender and similar), including cheat files inside Sandboxie's container folder.
- A **PC ID**: a scrambled ID made from which PCIe hardware the PC has (like the graphics and network card models). No serial numbers are read for it. The same PC gets the same ID, so staff can tell if someone checks a different PC. Two identical prebuilt PCs can share an ID.
- Renamed or unknown cheats, without relying on names:
  - any `autoexec` folder (executors run scripts from it)
  - Roblox scripts that use executor-only functions
  - programs run from Downloads, Desktop, Documents or Temp while a Roblox game was open that have been deleted since
  - where downloaded programs and archives in Downloads and Desktop came from (Windows notes the website on every download). Only known cheat sites and ad-link "key system" sites are reported; other websites are never written down.
  - kicks in Roblox's logs: Roblox's own anti-cheat (error 268) and games kicking the player for exploiting
  - Windows Security being turned off or given exclusions in the last 30 days, even if it was turned back on

**What it never does**
- Never deletes, moves or changes anything.
- Never connects to the internet. There is no upload code in the app. You choose whether to copy or save the report.
- Never reads passwords, browser history, Discord, photos or documents.
- Never installs itself or keeps running after you close it.

Automated tests check these promises on every build (see [SECURITY.md](SECURITY.md)).

It asks for admin because Windows only lets admins **read** Prefetch, the change log and the Security event log.

The report only lists matches. Names of your other files are never written down. Your Windows user name is replaced with `~` in every path.

## Settings
The gear icon opens Settings. Performance settings only change how deep and how fast the check runs, never what it's allowed to do.

- **Scan depth**: Quick (about 30 seconds, Windows drive only), Standard (1 to 2 minutes, recommended), or Thorough (3 to 5 minutes, deeper folders and the full change log).
- **Low CPU mode**: runs at low priority so games and other apps stay smooth.
- **Check other drives**: include or skip drives like D: and E:.
- **Fingerprint matches**: add a SHA-256 to each cheat file found.
- **Theme** (System, Light, Dark) and **Reduce motion**.

The scan depth used is printed on every report, so moderators can ask for a Standard or Thorough check if someone ran a Quick one.

## Verify your download
Every release lists the SHA-256 of `OpenCheck.exe`. The same fingerprint is printed at the top of every report, so a moderator can tell if someone used a modified copy.

Each release also carries a **build attestation**: signed proof from GitHub that it was built from this repository's public code. To check it, install the [GitHub CLI](https://cli.github.com) and run:
```
gh attestation verify OpenCheck.zip --repo OWNER/REPO
```
Replace `OWNER/REPO` with this repository's name.

## For moderators

Read the **[staff guide](STAFF-GUIDE.md)** for how to run a check that can't be faked, and the **[threat model](THREAT-MODEL.md)** for every known way to beat a check and what catches it.

1. Send the player the link to this repo's Releases page.
2. They run it, tick the box and press **Start check**. It takes about 1 to 2 minutes.
3. They press **Copy for Discord** and paste it in your channel, or **Save report** and attach the `.txt` file. You can also watch it live over a screenshare.
4. **Check the app's SHA-256** in the report against the release notes. If it doesn't match, the app was modified.

**Reading the results**
- **Flagged**: something on the cheat list was found, ran, was deleted, or is excluded from antivirus.
- **Needs review**: no cheat names matched, but there are signs worth asking about: cleared logs, a reset change log, Prefetch wiped, a VM, a DMA-style device, unfair FastFlags.
- **Clean**: nothing matched.

A match is evidence, not proof. Files can be renamed, and an innocent file can share a name. Several sources agreeing (for example Prefetch + BAM + a USN deletion a few minutes later) is much stronger than one. A clean result doesn't guarantee the PC is clean. A determined cheater can use a second PC, a renamed build the list doesn't know, or a DMA card with custom firmware. Make the final call yourself.

## Building

### On GitHub (how official releases are made)
1. Every push to `main` runs **Build and test** in the Actions tab. If a test fails, nothing is built.
2. To publish a release, create a tag like `v1.0.0` (Releases > Draft a new release > choose a tag). The workflow builds the app, attaches `OpenCheck.zip` and `SHA256SUMS.txt`, adds the hashes and verify instructions to the release notes, and creates the build attestation.
3. Edit the release notes to fill in "What changed" and the VirusTotal link.

### On your own PC (for testing only)
1. Install the free [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).
2. Double-click `build.bat`. It runs the tests, then builds into the `out` folder.

Only share builds from GitHub Releases. A build from your own PC has a different fingerprint and no attestation.

The app targets .NET Framework 4.8 and uses Microsoft Edge WebView2. Both ship with Windows 10 and 11, so players don't need to install anything.

## Updating the cheat list
Edit `src/PCCheck/signatures.json` and push. The list is compiled into the `.exe`, so the person being checked can't edit it. Each entry explains itself:
- `match`: name tokens. Spaces, dashes and dots are ignored.
- `strict: true`: only exact names (plus suffixes like `UI`, `Bootstrapper`, `V3`). Use this for short or common words like Wave or Xeno so normal apps aren't flagged.
- `folders`: known install folders, like `%ProgramData%\Solara`.
- `knownBadSha256`: optional fingerprints of exact cheat builds, to catch renamed copies in Downloads and Desktop.

Bump `version` at the top so reports show which list was used.

## Antivirus and "Unknown publisher"
New unsigned `.exe` files get a SmartScreen warning, and a few antivirus engines may flag them by guesswork. This app keeps the risk low: no packing or obfuscation, no network code, no hidden processes, full file details.

- **Signing** removes the warning. Free for open-source projects through [SignPath Foundation](https://signpath.org) if accepted, or about $10 a month with [Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/). Both work with GitHub Actions.
- **False positives**: if an engine flags a release, report it rather than hiding it. Microsoft: <https://www.microsoft.com/wdsi/filesubmission>. Most vendors have a similar form, linked from the VirusTotal result.

## License
MIT. See [LICENSE](LICENSE).
