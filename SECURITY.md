# Security and privacy

OpenCheck reads a PC to look for Roblox cheat software. Because of that, it has to earn trust. These are its rules, and the tests in `tests/PCCheck.Tests/SafetyTests.cs` fail the build if the code ever breaks them:

- It only **reads**. It never deletes, moves or changes files, settings or the registry.
- It has **no network code**. Nothing leaves the PC unless the person copies or saves the report themselves.
- It never starts other programs or loads hidden code.
- The only files it writes are the reports the person chooses to save to their Desktop.

## Report a problem
If you find a bug that breaks one of these rules, or a security or privacy issue:

- Use **Report a vulnerability** on this repository's Security tab, so it stays private until it's fixed. Don't open a public issue for it.
- Include what you saw and how to reproduce it.

Reports are answered as soon as possible, and confirmed issues are fixed in a new release with a note in the release notes.

## Fake copies
The only official download is this repository's Releases page. OpenCheck never asks anyone to disable antivirus or add an exclusion. If you find a copy that does, or one whose SHA-256 doesn't match the release, please report it.
