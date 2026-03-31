# RDP-Forensic — Progress

## What Works

- [x] Local Sampler build compiles module successfully
- [x] Module exports Get-RDPForensics and Get-CurrentRDPSessions
- [x] Pipeline Build stage passes (GitVersion + pack)
- [x] All test files PS 5.1 compatible (nested Join-Path)
- [x] Matrix strategy for PS7 + PS51 in Unit and Integration jobs
- [x] GitVersion ContinuousDelivery configured (main branch)

## What's Left

- [ ] Verify pipeline passes end-to-end after push
- [ ] Integration tests likely need mocking (CI has no RDP event logs)
- [ ] Code coverage — may need adjustments to reach 85% threshold
- [ ] CHANGELOG.md — populate with actual release notes
- [ ] Deploy stage — test PSGallery publishing
- [ ] Wiki/docs generation (DscResource.DocGenerator removed)

## Known Issues

- `Join-Path` with 3+ args is PS 7+ only — always nest calls
- PSResourceGet V2 has bugs with Sampler — using ModuleFast instead
- Integration tests call real Windows APIs (Get-RDPForensics) — will fail without event logs
- Root-level .ps1/.psm1/.psd1 files are legacy copies (source/ is canonical)
