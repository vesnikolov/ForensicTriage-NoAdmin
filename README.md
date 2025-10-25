# Windows-Native Forensic Triage Script - NoAdmin
This repository contains a modular PowerShell script designed for forensic triage in environments with strict operational constraints. It was developed and tested on Windows to support investigations of internal data exfiltration without requiring administrative privileges or third-party tools.

## 🔍 Problem Context
The script was created in response to suspected internal data exfiltration within a remote infrastructure handling sensitive and classified information. Due to security policies, administrative access and external forensic tools were prohibited. The solution had to be:
- Executable by non-privileged IT personnel
- Based solely on built-in Windows utilities
- Reproducible and minimally invasive
- Interpretable by technical and non-technical stakeholders

## 🛠️ Features
- Modular architecture using `Invoke-Action` blocks
- Collection of:
  - Event logs (Security, System, Application)
  - Installed software (registry-based)
  - PowerShell command history
  - Scheduled tasks and USB device traces
  - System snapshot and prefetch metadata
- Unified timeline construction
- SHA256 hashing for data integrity
- Excel workbook export and Power BI visualization
- ZIP packaging for portability

## 📈 Visualization
The exported Excel workbook is designed for ingestion into Power BI, enabling rapid triage and stakeholder-friendly interpretation. Dashboard fields include:
- Timestamp
- User
- Event Source
- Event Name
- Description

## 🔁 Reusability
The script is designed for reuse in future incidents under similar constraints. It requires no elevated privileges and functions in low-connectivity environments.

## 📄 License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🧠 Attribution
Developed and tested with assistance from Copilot and Ghat GPT to support academic and operational forensic workflows.
