## Volatility plugin contest 2022 Submissions - Rootkits and fileless detection
### Asaf Eitani

<br>

## Table of content
<!-- TOC start -->
- [Abstract](#abstract)
- [Previous work](#previous-work)
- [Changes/additions to Volatility core plugins](#volatility-changes)
  - [Changes made in the Volatility framework](#volatility-framework-changes)
- [Rootkit detection](#rootkit)
  - [Sequence operations hooking detection](#seqops)
  - [File operations hooking detection](#fops)
  - [Fileless detection](#fileless)
- [Why should I win the contest?](#why-should-I-win-the-contest)
<!-- TOC end -->

<br>

## Abstract <!-- TOC --><a name="abstract"></a>
The objective of this project is to create a suite of Volatility 3 plugins for advanced rootkit capabilities detections on Linux systems.
By its nature - rootkits tend to remain undetected in infected systems.
They manage to do so by hiding themselves and other malware on the system, mainly by placing hooks on system functions such as directory listing and file access.
Although Volatility suplies the `detect_syscalls` plugin which should detect syscall hooking, threat actors have advanced to more sophisticated hooking methods.
In the submission I added two more hooking methods - Sequence operations hooking and file operations hooking, intended to hide network connections and files respectively.
Another plugin included in this submission is the `fileless` plugin - intended to detect fileless process creations, process which were created from temporary file systems or their binaries were deleted after execution while they are still running.

An overview of how the plugins work is supplied below.

<br>

## Previous work <!-- TOC --><a name="previous-work"></a>
This submission make use of last years' contest winner plugins - <a href="https://github.com/amir9339/volatility-docker">Amir Sheffer with the docker plugin</a>.
His work included extensive contribution to files and mount detection which this plugin is heavily dependent on.
This work is included in the `volatility3_changes` directory.
<br>

## Changes/additions to Volatility core plugins <!-- TOC --><a name="volatility-changes"></a>

<br>

### Changes made in the Volatility framework <!-- TOC --><a name="volatility-framework-changes"></a>

To enable detection of non default function pointed by either the Sequence of the file operations struct, I added helpers function to the utility script of Volatility3.
Those helpers are `find_module_owner_by_address` and `get_address_symbols` both of which are intended to provide insight into which kernel modules the hooking functions reside on.

`find_module_owner_by_address` - return the kernel module owner of the provided address or `UNKNOWN` if non was found.
`get_address_symbols` - returns all symbols referencing to the provided address as a string or `UNKNOWN` if non was found.

<br>

## Rootkit detection <!-- TOC --><a name="rootkit"></a>

<br>

### Sequence operations hooking detection <!-- TOC --><a name="seqops"></a>
<br>
The `check_seqops` plugin is used to detect hooking on network `seq_operations` structs.
Sequnece operations hooking is performed by kernel rootkits to avoid detection of network related activity.
The network symbols checked are:
- `tcp4_seq_ops`
- `tcp6_seq_ops`
- `udp_seq_ops`
- `udp6_seq_ops`
- `raw_seq_ops`
- `raw6_seq_ops`

For each, the 4 operations functions pointers are checked for a hook:
- `start`
- `stop`
- `next`
- `show`

The plugin determines if one of the operations function pointers is pointing to an area outside of the compiled kernel - defined by `s_text` and `e_text`.
If such a hook was found, the following information is displayed:
- `Struct Name` - The name of the hooked stuct, one of the network symbols mentioned above.
- `Struct Member` - The name of the hooked function pointer, one of the operations functions pointers mentioned above.
- `Function Address` - The address pointer by the function pointer, which is outside of the compiled kernel.
- `Function Symbols` - Any symbols that are associated with `Function Address`. Unless the kernel symbols were taken from the victim machine in the time of the attack, this Value will probably be `UNKNOWN` as the hooking function usually resides in the malicious kernel module address space.
- `Function Owner` - The kernel module in which `Function Address` resides.


### File operations hooking detection <!-- TOC --><a name="fops"></a>
<br>
The `check_fops` plugin is used to detect hooking on `file_operations` structs.
File operations hooking is performed by kernel rootkits to avoid detection of file system related activity.
Mostly used to hide files, directories and processes from the `procfs`.

The plugin determines if one of the operations function pointers is pointing to an area outside of the compiled kernel - defined by `s_text` and `e_text`.

This plugin operates by iterating over each file on the system with the execptions for files that resides in a kernel module.
Files like those has their operation pointers point to their kernel module and thus we are unable to detect hooking in the current detection method.

Each operations function pointer for each file in the memory image is being checked.

If a hook was found, the following information is displayed:
- `Fops Addr` - The address of the `file_opeartions` stuct which one of its pointers were hooked.
- `Fops Member` - The name of the hooked function pointer. Functions like `iterate` or `read` are the most common ones.
- `Member Address` - The address pointer by the function pointer, which is outside of the compiled kernel.
- `Func Symbols` - Any symbols that are associated with `Function Address`. Unless the kernel symbols were taken from the victim machine in the time of the attack, this Value will probably be `UNKNOWN` as the hooking function usually resides in the malicious kernel module address space.
- `Func Owner` - The kernel module in which `Function Address` resides.
- `Mount ID` - The mount ID of the file with the hooked operation function.
- `Inode ID` - The Inode ID of the file with the hooked operation function.
- `Inode Address` - The Inode address of the file with the hooked operation function.
- `Mode` - The mode of the file with the hooked operation function.
- `UID` - The UID value of the file with the hooked operation function.
- `GID` - The GID value of the file with the hooked operation function.
- `Size` - The size of the file with the hooked operation function.
- `Created` - The creation time of the file with the hooked operation function.
- `Modified` - The modification time of the file with the hooked operation function.
- `Accessed` - The last access time of the file with the hooked operation function.
- `File Path` - The file path.


### Fileless detection <!-- TOC --><a name="fileless"></a>
<br>

## Why should I win the contest? <!-- TOC --><a name="why-should-I-win-the-contest"></a>
