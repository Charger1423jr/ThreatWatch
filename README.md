# Threat Watch
### The Quick Script Supsicious File Locator
##### Preston Jackson

---

## What is at risk?

Malware comes in many forms, and can destroy a device from the inside. Detecting malware is 
an issue that still challenges modern Anti-Virus detectors to this day.

---

## What is Threat Watch?

- Script that scans PC files for suspicious files
- Creates a file storing the results of the scan

---

## How does it work?

1. Call upon the scanner method to begin the scan
2. For each file on device, store the path, name, filename, and the memory usage
3. Using checks, apply point values to each file the script has access to
4. Store each file in a report file

---

## How to Run
1. Ensure .NET Framework is installed on your device and you can access and run C# files
2. Open the Command Prompt at File Location
3. enter commands `dotnet build` and `dotnet run`

### Notes and Warnings
- This is not a Anti-Virus program
- This Program is not to be used as a defender system
- This Program is used to mark files that may be of note and need to be investigated
- The Whitelist domain.json list was not made by me, rather from the following GitHub Repo: https://github.com/trusteddomainproject/OpenDMARC
- This program was created with the intention of learning C# and .NET. I do not claim that this program will protect or detect malware from your device
