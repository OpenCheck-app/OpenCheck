# Staff guide: running a check that can't be faked

OpenCheck finds what's on the PC. These steps make sure it's really the player's PC, the real app, and the real result. Software alone can't do that part.

## Before the check
1. Get on a **live screenshare** with the player (Discord stream of their whole screen, not one window).
2. Have them open **your website** and press **Download**, while you watch. Don't accept a copy they already had.
3. They unzip it and run `OpenCheck.exe`. If Windows asks for admin, they click **Yes**. A check without admin is incomplete.

## While it runs
4. Watch the whole scan (1 to 2 minutes). If they switch windows, minimize it, or close it early, start over.
5. Scan depth should be **Standard** or **Thorough**. Ask for a redo if it says Quick.

## Check these on their screen
6. **Version:** the newest one (top left of the app, and the first lines of the report).
7. **Fingerprint (SHA-256):** the first 16 characters in the report must match `SHA256SUMS.txt` on the release page.
8. **PC ID:** write it down. If a player's PC ID changes between checks, ask why: a different PC, a new graphics card, or a VM.
9. **Admin: yes.**

## Reading the result
- **Flagged:** something on the cheat list was found, ran, was deleted, or is hidden from antivirus. Open each item: the strongest evidence is listed first.
- **Needs review:** no named cheat, but something worth asking about: cleared logs, a reset this week, a VPN, a deleted program that ran during a game, internet drops during games, a sandbox or spoofer. Ask the player about each one.
- **Clean:** nothing matched. Strong evidence, not a guarantee.

Several pieces of evidence that agree (for example: the loader ran during a game, was deleted minutes later, and Roblox kicked them with error 268) are much stronger than one. One name match on its own could be a coincidence, so ask.

## When to escalate
- They refuse a screenshare, or the report text doesn't match what you saw: treat it as a failed check.
- A clean report but their gameplay still looks wrong: do a **VOD review**, and for high-stakes cases ask for a short video of the desk and the back of the PC (second PC, capture card, DMA card, input boxes).
- A **Needs review** with tampering (cleared logs, a reset or deleted Roblox logs right before the check): ask for a recheck in a few days and a VOD.

## Never
- Never ask a player to turn off their antivirus or add an exclusion. OpenCheck never needs it.
- Never accept OpenCheck from anywhere except your website or the GitHub Releases page.
