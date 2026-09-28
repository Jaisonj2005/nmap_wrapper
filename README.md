# Nmap GUI Automation Wrapper 🗺️

A Python graphical frontend designed to simplify and automate the execution of the Nmap Security Scanner. Built for Tier 1 SOC Analysts to perform rapid network reconnaissance without memorizing complex CLI syntax.

**Features:**
* Integrates directly with the system's native Nmap executable via the `python-nmap` library.
* Maps user-friendly dropdown profiles directly to standard Nmap flags (e.g., `-sn`, `-F`, `-A`, `-O`).
* Utilizes Python `threading` to ensure the GUI remains fully responsive during long-running aggressive scans.
* Parses complex XML/JSON Nmap outputs into a highly readable, color-coded SOC terminal display.

*Built as Day 16 of a 30-Day Network Engineering & Security portfolio streak.*
