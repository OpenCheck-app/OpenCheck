# OpenCheck threat model

OpenCheck is open source, so assume cheaters can read every rule. That's fine: the checks rely on records Windows keeps by itself, which are hard to erase without leaving a bigger trace. Every bypass below is listed with the trace it leaves and what catches it. A row marked **Process** is covered by how staff run the check (see [STAFF-GUIDE.md](STAFF-GUIDE.md)), because no software running on the player's PC can fully cover it.

Coverage: **Strong** = caught in normal cases · **Partial** = caught often, or flagged for review · **Process** = staff procedure · **None** = out of reach for a PC check.

## Hiding the cheat

| Bypass | Trace it leaves | Caught by | Coverage |
|---|---|---|---|
| Delete the cheat before the check | Drive change log (USN), Recycle Bin, Prefetch, BAM, compatibility cache (ShimCache), the program launch log (PCA), Windows Defender's own log, crash reports | Deleted files, Programs that ran | Strong |
| Rename the cheat | Same file fingerprint; executor folders (workspace, autoexec); the file set it keeps together (e.g. Matrix's `mcache.dat` + `_license.dat`); scripts with executor-only functions; the website it was downloaded from | Fingerprints, folder and file-set layouts, script contents, download source | Strong |
| Brand-new or private cheat not on any list | Program run from Downloads/Desktop/Temp during a Roblox game, then deleted; Windows-named program in a personal folder; Roblox anti-cheat kick (error 268); download from a cheat or key-system site | Behavior checks | Partial |
| Rename it after a Windows program (`svchost.exe` in Downloads) | BAM records the real path | Disguised program check | Strong |
| Encrypted cheat that only exists in memory (like Matrix's `version.dat`) | The loader still runs from disk; its files sit together | Loader name and fingerprint, file set, Programs that ran | Strong |
| Run it from a USB stick or external drive | Windows device log (USB plugged in), BAM path on a drive that's not connected now | USB history, programs run from USB | Partial |
| Run it from a RAM disk | RAM disk software installed | RAM disk tool | Partial |
| Run it inside Sandboxie or another sandbox | Sandbox software, `C:\Sandbox` box folder (cheat files are scanned inside it) | Sandbox and freeze tools | Strong |
| Deep Freeze / Shadow Defender wipe every change at reboot | Freeze software installed | Sandbox and freeze tools | Strong |
| Use another Windows account on the same PC | Every account's folders and BAM records are read | All checks cover every profile | Strong |

## Wiping the records

| Bypass | Trace it leaves | Caught by | Coverage |
|---|---|---|---|
| Clear event logs | Event 1102/104 (log cleared), suspiciously short logs | Logs, resets and firewall | Strong |
| Delete the drive change log (`fsutil usn deletejournal`) | Change log created after Windows was installed | Deleted files | Strong |
| Wipe Prefetch, or turn it off | Bulk Prefetch deletions in the change log; Prefetch setting = 0 | Deleted files, Programs that ran | Strong |
| Delete Roblox's logs | Roblox ran (Prefetch) but no log covers that time; bulk log deletions | Roblox game history | Strong |
| Clean recent-file history (CCleaner, BleachBit, PrivaZer) | Bulk jump-list deletions; cleaner installed or run; the cheat is still in the PCA launch log and Defender's log, which cleaners don't touch | Trace cleaners, Programs that ran | Strong |
| Wipe records by hand with commands (`fsutil usn deletejournal`, `wevtutil cl`, deleting Prefetch, BAM or UserAssist) | The commands stay in PowerShell history | Cleanup commands typed | Partial |
| Injected cheat DLL with no name we know | If Roblox ever crashed with it loaded, Windows' crash report lists it | Roblox crash reports | Partial |
| External cheat that loads a kernel driver (kdmapper and similar) | Service install event 7045 with a driver in Temp or Downloads, even after it's deleted | Installed drivers | Strong |
| Change the PC clock | Event 4616 (time changed) | Logs | Strong |
| Reset or reinstall Windows | Install date, "Source OS" record, new account | PC resets | Strong (it shows the reset; what was there before is gone) |
| Turn off Windows Security or add exclusions | Defender events 5001/5007, exclusions in the registry | Windows Security history | Strong |

## Faking the check

| Bypass | Trace it leaves | Caught by | Coverage |
|---|---|---|---|
| Paste an edited or old report | Report text can't prove itself (anyone can edit text) | Staff watch it run live | Process |
| Run a modified OpenCheck that hides findings | The fingerprint changes. A modified build can also lie about its own fingerprint, so it has to be checked from outside | Fresh download from the website during a screenshare; the build attestation; code signing once added (Properties → Digital Signatures) | Process |
| Run the check on a different PC | Different PC ID; different Windows name | PC ID on every report | Strong if staff note PC IDs |
| Run the check in a virtual machine | VM hardware, MAC address, drivers | VMs and emulators | Strong |
| Change hardware serials with a spoofer | Spoofer software installed. The PC ID uses hardware **models**, not serials, so it doesn't change | HWID spoofer, PC ID | Strong |
| Cheat only between checks | Nothing, if the PC is spotless at check time | Random or repeat checks, VOD review | Process |

## Out of reach for any PC check

| Bypass | Why | What to use instead |
|---|---|---|
| Cheat on a second PC (colorbot through a capture card, DMA with custom firmware) | Nothing runs on the checked PC | VOD review, a short video of the desk and the back of the PC |
| A perfect custom-firmware DMA card | It copies a real device exactly | VOD review; OpenCheck still flags cheap DMA cards, driverless PCIe devices and recent PCIe installs |

## Keeping this current

- Every missed cheat gets a regression test in `tests/PCCheck.Tests/ParserTests.cs`, using what that cheat actually leaves on a PC (like `MatrixRegressionTests`).
- Rules live in `signatures.json`. Names are the weakest signal, so prefer fingerprints, file sets, folder layouts and behavior.
- Every build is scanned with Microsoft Defender before release, and the safety tests must pass.
