<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/RyanB86/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "arklab" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `edge_checkout_page_validator.js` on the desktop at `2025-07-05T19:49:52.1224649Z`. These events began at `2025-07-05T19:49:52.1224649Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == 'arklab'
| where InitiatingProcessAccountName == 'arklab'
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-05T19:49:52.1224649Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account =InitiatingProcessAccountName

```
<img width="1212" alt="image" src="<img width="1436" height="884" alt="Screenshot 2025-07-15 125646" src="https://github.com/user-attachments/assets/48bdf4f5-b882-4c1d-9bb3-ac770f0046ce" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-07-05T19:51:25.0126895Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.4.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == 'arklab'
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1212" alt="image" src="<img width="1401" height="757" alt="Screenshot 2025-07-15 131351" src="<img width="1410" height="721" alt="Screenshot 2025-07-15 131550" src="https://github.com/user-attachments/assets/760e968d-2f7a-4b0c-b73a-5dff9c5efa6d" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-07-05T20:18:38.4840384Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == 'arklab'
| where FileName has_any ("tor.exe", "tor.firefox", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1212" alt="image" src="<img width="1416" height="753" alt="Screenshot 2025-07-15 132220" src="https://github.com/user-attachments/assets/5ac80646-6e5c-460b-b73b-e2c08963a8c0" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-07-05T20:18:40.0814438Z an employee (arklab) on the “arklab” device successfully established a connection to the remote IP address 127.0.0.1 on port 9151. The connection was initiated by the process tor.exe, located in the folder c:\users\arklab\desktop\tor browser\browser\firefox.exe. There were a few other connections over sites to port 443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == 'arklab'
| where InitiatingProcessAccountName != 'system'
| where InitiatingProcessFileName in ('tor.exe', 'firefox.exe')
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

```
<img width="1212" alt="image" src="<img width="1844" height="684" alt="Screenshot 2025-07-15 132917" src="https://github.com/user-attachments/assets/68ec3cdb-a359-49dc-b2b9-23b4877a894c" />

---

Below is a timeline reconstruction showing when Tor was downloaded, installed, and used on the "arklab" workstation:

## Chronological Event Timeline 


### 1. File Download - TOR Installer
 User arklab downloaded Tor installer and extracted its components on the desktop, creating various Tor-related files (e.g., tor-browser.exe, and suspicious edge_checkout_page_validator.js).
 
- **Timestamp:** `2025‑07‑05T19:49:52.1224649Z`
- **Event:** The user "arklab" downloaded a file named `tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\arklab\Desktop`

### 2. Process Execution - TOR Browser Installation
The Tor Browser installer was launched from the Downloads folder by user "arklab". The action generated a process with a recorded SHA256 to verify integrity

- **Timestamp:** `2025‑07‑05T19:51:25.0126895Z`
- **Event:** The user "arklab" executed the file `tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor‑browser‑windows‑x86_64‑portable‑14.5.4.exe`
- **File Path:** `C:\Users\arklab\Downloads`

### 3. Process Execution - TOR Browser Launch
Evidence shows Tor (via tor.exe) actually ran for the first time, indicating the Tor Browser was opened.

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network
 Shortly after launch, the Tor Browser process successfully connected to 127.0.0.1:9151, establishing standard internal communication between Firefox and the Tor client.
 
- **Timestamp:** `2025‑07‑05T20:18:40.0814438Z`
- **Event:** A network connection to IP `127.0.0.1:9151` on port ` 9151 ` by user "arklab" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `…\Desktop\Tor Browser\Browser\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
