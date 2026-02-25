# CLONADISCOS

## Fast disk cloning for Windows. Pipe streaming, zero temp files.

CLONADISCOS clones entire disks partition by partition using wimlib pipe streaming. Data flows directly from source to destination through a pipe (`wimlib capture | wimlib apply`) - no intermediate .WIM file, no temp disk space needed.

**Website:** https://clonadiscos.com

---

## Why CLONADISCOS?

Clonezilla requires a bootable USB and a Linux environment. Macrium Reflect went paid-only. Neither runs natively on Windows.

CLONADISCOS is a single PowerShell script. Double-click, pick source, pick destination, done.

| Aspect | CLONADISCOS | Clonezilla | Macrium Reflect |
|--------|-------------|------------|-----------------|
| Price | Free, MIT | Free, GPL | Paid ($70/year) |
| Runs on | Windows (native) | Bootable USB (Linux) | Windows |
| Temp space | Zero (pipe streaming) | Depends on mode | Image file required |
| Speed | 100-200+ MB/s | Varies | Varies |
| GPT/UEFI | Full support | Yes | Yes |
| EFI partition | Cloned + bootloader repaired | Yes | Yes |
| GUI | Yes (WinForms Tron style) | ncurses | Full GUI |
| Script size | ~6,000 lines PowerShell | ISO image | 200+ MB installer |
| Dependencies | wimlib (auto-downloaded) | Built-in | Proprietary |
| VSS snapshots | Yes, with auto-fallback | No | Yes |
| Source code | Open, auditable | Open | Closed |

---

## Features

- **Pipe streaming** - `wimlib capture SOURCE - | wimlib apply - DEST`. No temp files. Data goes straight from disk A to disk B
- **Zero temp space** - Previous versions created intermediate .WIM files. v3.0 eliminated that entirely
- **Auto wimlib download** - First run downloads wimlib automatically. No manual setup
- **VSS snapshot fallback** - Uses Volume Shadow Copy for internal disks. If VSS fails, retries without it automatically
- **Full GPT/UEFI support** - Detects and clones EFI, MSR, Recovery, and data partitions. Repairs bootloader with `bcdboot`
- **Anti-interference protection** - Locks drives during cloning. Blocks Explorer access, Windows Indexer, and accidental USB removal
- **Double confirmation** - Critical actions require typing the keyword (e.g., "CLONAR") plus a second confirmation
- **Real-time monitor** - JSON-based progress file. Companion GUI monitor shows speed, ETA, and per-partition progress
- **SMART health check** - Pre-clone disk health analysis (temperature, errors, wear level for SSDs)
- **Disk image creation** - Create VHDX/WIM backup images. Restore from image to disk
- **FIERY mode** - Specialized cloning for Fiery RIP print controllers
- **Hidden disk rescue** - Recover disks that Windows hides (offline, no letter assigned)
- **Singleton mutex** - Only one instance runs at a time
- **Detailed logging** - Every operation logged with timestamps to `%USERPROFILE%\Documents\ARCAMIA-MEMMEM\Logs\`

---

## Installation

### Option 1: GUI Launcher (recommended)
```
Double-click CLONADISCOS-GUI.bat
```
Opens the WinForms GUI with three buttons: Clone Disk, Terminal, Exit.

### Option 2: Terminal
```batch
:: Double-click or run:
CLONADISCOS.bat
```
Opens the interactive terminal menu with full feature access.

### Option 3: Direct parameters (automation)
```powershell
# Clone disk 1 to disk 2 directly (skips menu)
powershell -ExecutionPolicy Bypass -File CLONADISCOS.ps1 -SourceDisk 1 -DestDisk 2
```

---

## How It Works

```
PHASE 1/3: Prepare destination disk
  - Clean destination, create partition table (GPT/MBR matching source)
  - Create partitions mirroring source layout
  - Format each partition (NTFS for data, FAT32 for EFI)

PHASE 2/3: Clone via pipe streaming
  For each partition:
    wimlib-imagex capture X:\ - --no-acls --compress=none | wimlib-imagex apply - Y:\ --no-acls
  EFI partition: robocopy (more reliable for FAT32)

PHASE 3/3: Bootloader repair
  - bcdboot for UEFI/BIOS boot configuration
  - Mark boot partition as active (MBR disks)
```

No compression (`--compress=none`) maximizes throughput. The pipe means data never touches your temp drive.

---

## Screenshots

<!-- TODO: Add screenshots -->
| Screen | Description |
|--------|-------------|
| ![Main Menu](screenshots/menu.png) | Interactive arrow-key menu |
| ![Cloning](screenshots/cloning.png) | Live progress during pipe streaming |
| ![Complete](screenshots/complete.png) | Summary with speed and duration |
| ![GUI Launcher](screenshots/launcher.png) | WinForms Tron Legacy GUI |

---

## Menu Structure

```
MAIN MENU
  [0] View connected disks
  [1] CLONE DISK           <- wimlib pipe streaming, 100-200+ MB/s
  [3] Wipe disk            <- Quick format, GPT + NTFS
  [4] Advanced wipe         <- Secure erase, choose format
  [5] Advanced options
      [1] Create disk image (VHDX/WIM)
      [2] Restore image to disk
      [3] View saved images
      [H] Health Check (SMART)
      [R] Rescue hidden disk
      [O] Hide disk from Explorer
      [L] Clean orphan drive letters
      [B] FULL clone (EFI+MSR+Recovery)
      [Q] QUICK backup (non-bootable)
      [F] FIERY mode (print RIP controllers)
      [D] Disk Management (Windows)
      [E] Disk Cleanup (Windows)
  [R] Refresh Explorer
  [6] View logs
  [X] Exit
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Windows 10 / Windows 11 |
| PowerShell | 5.1+ (included in Windows) |
| .NET | 4.8 (included in Windows 10/11) |
| Permissions | Administrator (auto-elevates) |
| wimlib | Auto-downloaded on first run |
| Disk space | Zero extra (pipe streaming) |

---

## Safety

CLONADISCOS protects your Windows drive by default:

1. **Windows disk excluded from destination** - The disk containing Windows cannot be selected as clone target
2. **Double confirmation** - You must type "CLONAR" and confirm again before any destructive operation
3. **Drive locking** - During cloning, involved drives are hidden from Explorer and blocked from user access
4. **Bootloader repair** - After cloning a bootable disk, `bcdboot` configures the new disk to boot correctly
5. **VSS auto-fallback** - If Volume Shadow Copy fails on a locked volume, automatically retries without it
6. **Singleton** - Mutex prevents running two instances simultaneously

---

## Project Structure

```
_DEV\
  CLONADISCOS.ps1           <- Main script (~6,000 lines)
  CLONADISCOS-Launcher.ps1  <- GUI launcher (WinForms, Tron Legacy style)
  CLONADISCOS-Monitor.ps1   <- Real-time progress GUI
  CLONADISCOS.bat           <- Terminal launcher
  CLONADISCOS-GUI.bat       <- GUI launcher shortcut
  clonadiscos.ico           <- App icon
  tools\
    wimlib-imagex.exe        <- Auto-downloaded
    libwim-15.dll
```

---

## License

MIT License. See [LICENSE](LICENSE).

wimlib is licensed under GPL v3. It is downloaded separately on first run and is not bundled with this repository.

---

## Links

- **Website:** [clonadiscos.com](https://clonadiscos.com)
- **Author:** [DTHCST](https://github.com/dthcst)
- **Sister project:** [Fregonator](https://github.com/dthcst/fregonator) - PC optimizer for Windows (250K+ views on Reddit)

---

Built by Martin Caamano Castineira / [DTHCST](https://github.com/dthcst)
