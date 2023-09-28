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
- disk image files, two of them encrypted using BitLocker
- VeraCrypt container
- Original BitLocker recovery key file
- Two txt-files containing a BitLocker recovery key
![](/Demo/01.png?raw=true)

Script in action<br>
![](/Demo/02.png?raw=true")

Results are stored to csv, key files are copied to the result folder.<br>
![](/Demo/03.png?raw=true")

The VeraCrypt container was successfully detected - be aware that there can be a lot of false-positives like cache-files in this example from chrome...<br>
![](/Demo/04.png?raw=true")

The recovery keys were successfully detected.<br>
![](/Demo/05.png?raw=true")

All disk image files were successfully detected.<br>
![](/Demo/06.png?raw=true")

The original BitLocker recovery key file was successfully copied.<br>
![](/Demo/07.png?raw=true")

