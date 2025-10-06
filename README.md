<div align="center">
  <h1>ChoomCore Tweaks</h1>
</div>

<div align="center">
  <h4>PowerShell toolkit for enthusiasts, advanced users, and gamers: extreme privacy, optimization, and bloatware removal.</h4>
</div>

---

## ✨ About ChoomCore Tweaks

ChoomCore Tweaks is a highly specialized collection of PowerShell scripts designed to give you **total control** over your Windows installation. The project focuses on three core pillars: **extreme performance optimization**, **data privacy**, and **aggressive bloatware removal**.

---

> [!WARNING]
> **USE AT YOUR OWN RISK**
> 
> This script performs deep modifications to the Windows Registry, services, and scheduled tasks.
> 
> * **It is NOT recommended for use on Notebooks/Laptops.** The aggressive nature of the tweaks **may disable essential services** like power management, Wi-Fi, Touchpad, and other specialized hardware drivers. Only use this on Desktop PCs.
> * **Recommendation:** Always create a **System Restore Point** before running any system-modifying script.

---

## 🚀 Key Features

This collection of tweaks focuses on aggressive optimization and security.

### 🔒 Core Privacy & Telemetry
* Disables **DiagTrack**, **Connected User Experiences and Telemetry**, and other usage tracking services.
* Sets **Telemetry Level to 0** in the Registry and disables SmartScreen.

### 🗑️ Bloatware & Appx Removal
* **Uninstalls over 30 AppX Packages** (e.g., YourPhone, ZuneVideo).
* Disables unnecessary optional features like **SMB1** and **WSL**.

### 🚀 Optimization & Performance
* Reduces **MenuShowDelay** and shortens the system's waiting time for frozen apps.
* Disables Clipboard History, File History, and unnecessary file access logging.

### 🎮 Gaming & Multimedia
* **Completely disables GameDVR/Game Bar** functionality.
* Stops services known to cause input lag (**MapsBroker**, **Spooler**) and disables OneDrive auto-start.

### 🛡️ Security & Hardening
* Disables obsolete protocols (**SSL/PCT**).
* Turns off administrative shares and removes app permissions for contacts/email.

---

## 🛠️ How to Run the Tweaks

> [!IMPORTANT]
> **YOU MUST RUN AS ADMINISTRATOR**
> 
> This script requires elevated privileges to modify system services and the registry. Always use the included **`RUN_ChoomCore.cmd`** file.

1.  **Download:** Download the two main files: `ChoomCore_Tweaks.ps1` and **`RUN_ChoomCore.cmd`**.
2.  **Execute:** Double-click **`RUN_ChoomCore.cmd`** to start the process.
3.  **Confirm:** Accept the User Account Control (UAC) prompt to allow the script to run as Administrator.

> [!NOTE]
> The `RUN_ChoomCore.cmd` uses the `-ExecutionPolicy Bypass` flag. This allows the script to run locally without changing your system's global security policies.

---

## 🤝 Contribution & License

Contributions and community feedback are encouraged to help improve this project. Please use the appropriate channel below:

* Report bugs or missing optimizations by opening a new **Issue**.
* Submit code improvements via a **Pull Request**.

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for full details.
