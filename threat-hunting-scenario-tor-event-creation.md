# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install: ```tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites. For example:
   - Current Dread Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion```
   - Dark Markets Forum: ```g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```elysiumyeudtha62s4oaowwm7ifmnunz3khs4sllhvinphfm4nirfcqd.onion```
6. Create a folder on your desktop called ```edge_checkout_page_validator.js```
7. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (("9001", "9030", "9050", "9051", "9150", "9151", "80", "443").|

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being installed
DeviceProcessEvents
| where ProcessCommandLine contains "tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe" 
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where DeviceName == 'arklab'
| where InitiatingProcessAccountName != 'system'
| where InitiatingProcessFileName in ('tor.exe', 'firefox.exe')
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc


// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "edge_checkout_page_validator.js"
```

---

## Created By:
- **Author Name**: Ryan Boose
- **Author Contact**: https://www.linkedin.com/in/rboose
- **Date**: June 1, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
1. Similar to past issues like CVE-2024‑21388, Microsoft Edge had a flaw where a private API allowed silent installation of extensions—no user consent required. If edge_checkout_page_validator.js leverages private APIs or hidden endpoints, an attacker could misuse it to embed unauthorized scripts or UI elements into checkout pages.

2. Overly Broad Permissions
The script interacts deeply with checkout pages—accessing DOM, parsing forms, injecting UI. If its permissions aren’t properly constrained, malicious actors could hijack it, inject rogue JavaScript, or exfiltrate sensitive user data (addresses, payment details)—a classic case of insufficient privilege containment.

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor`   
