## Volatility3 rootkit plugins
<br />

### Project Description

This repo contains a set of Volatility3 plugins that detect advanced rootkit hooking methods.

[A full (but readable) explanation of plugin details can be found in the contest submission document](docs/contest_submission.md)



### Plugins

- **`check_seqops`** - The `check_seqops` plugin is used to detect hooking on network seq_operations structs. Sequnece operations hooking is performed by kernel rootkits to avoid detection of network related activity.
- **`check_fops`** - The `check_fops` plugin is used to detect hooking on file_operations structs. File operations hooking is performed by kernel rootkits to avoid detection of file system related activity. Mostly used to hide files, directories and processes from the procfs.
- **`fileless`** - The `fileless` plugin is used to detect processes that were created from a temporary file (like /dev/shm/ or memfd:) or that their executable file was deleted after the process creation. This technique is often used to avoid detection of disk scanning security solutions and to avoid further investigation of the executable malware.


### ✔️ Prerequisites:

- Python 3
- Volatility 3

Install on Linux using these commands:

```bash
apt install python3
# clone from repo
git clone https://github.com/volatilityfoundation/volatility3.git
# or install as a module
pip3 install volatility3
```

### ⚙ Installation

All plugins are located in the `plugins` folder. Copy them to your Volatility 3 directory under `volatility3/volatility3/framework/plugins/linux`.

Some other framework extensions are required. They are located under `volatility3_changes`, and are organized in the same directory structure as their location within Volatility 3. Simply copy them to the same location (overwrite existing files if needed).
