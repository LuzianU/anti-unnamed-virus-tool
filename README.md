# Anti-Unnamed-Virus-Tool

The virus works by copying its malicious code to the end of most other executables on your drives, making them run that same spreading code next time one of them gets executed.
It also creates various weirdly named (3 to 5 letters) .exe files in the temporary directory.

It caused me to get very frequent ```The instruction at 0x* referenced memory at 0x*. The memory could not be written``` error popups and some applications only starting for a one-time use.

This script fully removes the virus code from infected executables and restores the files to their previous, uninfected version.

## How to run
- Install python
- ```pip install -r requirements.txt```
- ```python anti-unnamed-virus-tool.py``` with one of the argument options below.


## Arguments

```--scan SCAN [SCAN ...]```: Scans all `.exe` files in the specified directories. Multiple directories can be specified, separated by spaces. Example usage: `--scan 'C:\\' 'D:\\' 'E:\\'`.

```--file FILE``` Checks the specified file and removes the virus if found.

```--add```: Adds a 'Scan File' entry to the file explorer context menu. Clicking on it will run the --file command.

```--remove```: Removes the 'Scan File' entry from the context menu.

