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


### File operations hooking detection <!-- TOC --><a name="fops"></a>
<br>

### Fileless detection <!-- TOC --><a name="fileless"></a>
<br>

## Why should I win the contest? <!-- TOC --><a name="why-should-I-win-the-contest"></a>
