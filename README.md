# WileECoyote v0.3.1


A swiss army knife for baking shellcode runners.


Introduction
------------
WileECoyote.py is a Python 3.8 tool used for obfuscating Meterpreter and CobaltStrike shellcode by wrapping them in custom templates. 

Usage
-----
The framework as of v0.3.1 contains 10 unique methods for executing Meterpreter shellcode. The tool was developed to be modular so that other templates can be added in and built without modifying the core `WileECoyote.py` script. In some instances the tool utilizes some third party components like `Invoke-Obfuscation`, `Invoke-Dosfuscation`, `Invoke-PowerShellTcp.ps1`. Currently 2 methods for staged execution exist but will be removed prior to the passing of the OSEP exam. Staged files will be created with a future tool called `roadrunner.py`. The two scripts however are expected to work in tandem. 

Installation
------------

Installation can be done by issuing the following commands.  
```
pip3 install -r requirements.txt
sudo apt install -y mono-mcs
```

Release Notes
-------------

v0.3.1 - 2021-06-16: The first release containing 10 unique methods for executing Meterpreter shellcode. Additionally, two staged variants (hta, vba) have been added. The following runners have been added: 
  - Process Hollowing - Creates a hollowed `svchost.exe` process and injects 64-bit Shellcode into it. 
    - msbuild
    - standard
    - installutil
  - Process Injection - Uses the win32 API's `NtCreateSection`, `NtMapViewOfSection`, `NtWriteVirtualMemory`, `CreateRemoteThread` to inject shellcode into an existing `explorer.exe` process. 
    - msbuild
    - standard
    - installutil
  - Nishang - Uses MSBuild.exe to spawns a PowerShell ConstrainedLanguageMode Bypass (Custom Runspace). Runs an AMSI Bypass Method and downloads and executes Nishang's `Invoke-PowerShellTcp.ps1` in memory. 
    - msbuild
  - Executable - Standard windows executable.
    - standard
  - ASPX - Microsoft Windows Active Server Page Extended (ASPX) file containing obfuscated shellcode. 
    - standard
  - ELF - Standard Linux executable containing obfuscated shellcode. 
    - standard
