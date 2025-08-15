<p align="center">
<img src="https://github.com/Chainski/PandaCrypter/blob/main/assets/PandaCrypter.png?raw=true", width="400", height="200">
</p>
<p align= "center">
   <img src="https://img.shields.io/github/stars/Chainski/PandaCrypter?style=flat&color=%23fd5c50">
   <img src="https://img.shields.io/github/forks/Chainski/PandaCrypter?style=flat&color=%23fd5c50">
   <img src="https://hits.sh/github.com/Chainski/PandaCrypter.svg?color=fd5c50">
   <br>
   <img src="https://img.shields.io/github/last-commit/Chainski/PandaCrypter?style=flat&color=%23fd5c50">
   <img src="https://img.shields.io/github/license/Chainski/PandaCrypter?color=%23fd5c50">
   <br>
</p>

# PandaCrypter
PandaCrypter is a C#-based tool designed to convert PowerShell scripts into obfuscated batch files (.bat) with encryption and additional features for execution control. 

# Features
- [x] AES Encryption: Encrypts the PowerShell payload.
- [x] Anti-VM: Optionally evades virtualized environments.
- [x] Compression: Compresses the payload to reduce size before encryption.
- [x] Obfuscation: Obfuscates the generated batch file and powershel execution chain. 
- [x] AMSI Bypass: Optionally includes an `AMSI` (Antimalware Scan Interface) bypass to avoid detection.
- [x] Run as Administrator: Supports elevating privileges by prompting for admin rights using `Abuse Elevation Control Mechanism` [Force Admin](https://github.com/Chainski/ForceAdmin).
- [x] Self-Deletion: Optionally self-destructs after execution.
- [x] Persistence: Optionally registers the batch file to run at user logon via scheduled tasks.
- [x] Windows Defender Exclusion: Can add an exclusion path to Windows Defender (requires admin privileges).
- [x] Execution Delay: Supports adding a delay before script execution.
- [x] Low Entropy Packing: Contains colon padding to reduce entropy
- [x] EventLog Cleanup: Removes Powershell logs to reduce footprint (requires admin privileges).

# Tested with Red-Team Tools 
- [x] [Hoaxshell](https://github.com/t3l3machus/hoaxshell)

# Options
```
-debug: Debug mode
-amsi: Enables AMSI bypass in the generated batch file.
-antivm: Evades virtualized environments.
-admin: Configures the batch file to request administrative privileges.
-selfdelete: Adds self-deletion logic to remove the batch file after execution.
-startup: Registers the batch file to run at user logon using a scheduled task.
-defender_exclusion: Adds an exclusion path to Windows Defender for the ProgramData and UserProfile directory.
-sleep: Introduces a 10-second delay before executing the payload.
```

# How It Works
PandaCrypter processes a PowerShell script through several stages to produce an obfuscated batch file:

- Input Reading: Reads the input PowerShell script (.ps1) as text.
- Compression: Compresses the script using `GZip` to reduce its size.
- Encryption: Encrypts the compressed payload.
- Stub Generation: Creates a PowerShell stub that:
- Decodes the encrypted payload from Base64.
- Decrypts it using the provided `key` and `IV`.
- Decompresses the result.
- Executes the final PowerShell code using IEX `(Invoke-Expression)`.
- Batch Obfuscation: Embeds the PowerShell stub in a batch file, applying:
- Random variable names for obfuscation.
- Splitting commands into smaller parts assigned to variables.
- Random case variation for PowerShell command strings (e.g., pOwErShElL).
- Feature Integration: Adds optional features like `AMSI bypass`, `admin elevation`, or `self-deletion` based on command-line flags.
- Output: Writes the final batch file with the encrypted payload appended as a Base64-encoded string, prefixed with `::` .

# Installation
Clone the repository or download the prebuilt binary produced by github actions:
```
git clone https://github.com/chainski/PandaCrypter.git
```
Open the solution in Visual Studio or another C# IDE.
Build the project to generate the executable (PandaCrypter.exe).
Run the tool from the command line with the desired options.

# Usage Example 
```powershell
"Hello, World!" > hello.ps1
```

```batch
PandaCrypter -i hello.ps1 -o hello.bat 
```

# Contributing
Contributions are welcome! Please submit pull requests or open issues for bug reports, feature requests, or improvements.

# License
This project is licensed under the MIT License. See the file for details.

# Disclaimer
PandaCrypter is provided "as is" for educational and research purposes. The developers are not responsible for any misuse or damage caused by this tool. 
Always use it in compliance with applicable laws and regulations.
