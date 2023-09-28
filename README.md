# ENCScanner
Scan drive or directory for:
- BitLocker recovery key files
- encrypted containers
- disk image files


## Workflow
**Identify BitLocker key files**
- Check filename
- RegEx pattern search on TXT-Files

**Identify encrypted containers or disk image files**
1) filesize divided by 512 = whole number?
2) mime-type = "application/octet-stream"?
3) Entropy value > 7.9 ?
=> probably encrypted file
4) Check offsets 510-512 ("00 AA") or 512-519 ("EFI PART") ?
=> disk image file

## Demo
This is my demo folder containing:
- 5 disk image files, 2 of them encrypted using BitLocker
- VeraCrypt container
- Original BitLocker recovery key file
- 2 TXT-Files containing a BitLocker recovery key
![Demo folder](/Demo/01.png?raw=true "title")
