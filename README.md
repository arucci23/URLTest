# Phishing URL Checker

This PowerShell script checks if a given URL is flagged as phishing using the VirusTotal API.

## Features
- Queries VirusTotal to check if a URL is safe or flagged as phishing.
- Simple to use with minimal configuration.
- Includes basic error handling.

## Prerequisites
- A free VirusTotal API key (https://www.virustotal.com/).
- PowerShell installed (works with PowerShell 5.x and higher).

## How to Use
1. **Download the script** or clone this repository.
2. **Get a VirusTotal API key** at https://www.virustotal.com/gui/join-us.
3. **Edit the script**: Replace `YOUR_VIRUSTOTAL_API_KEY` with your actual API key.

   ```powershell
   # Replace with your actual API Key
   $apiKey = 'YOUR_VIRUSTOTAL_API_KEY'

