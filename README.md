# Network Reconnaissance Tool

## Overview
The Network Reconnaissance Tool is a Python-based application designed to facilitate network scanning and device mapping on local networks. It provides a graphical user interface (GUI) for users to specify an IP network range, initiate a network scan and display the discovered devices' information.

## Features
- Input fields for specifying IP network and network bits.
- Scan button to initiate the network scan.
- Progress bar to indicate scanning progress.
- Display of discovered devices' IP addresses and MAC addresses.
- Error handling for network scanning issues.

## Prerequisites
- Python 3.x
- Required Python packages:
  - tkinter
  - scapy

## Installation
1. Clone the repository to your local machine:
   ```bash
   git clone https://github.com/umQiLe/network-recon-tool.git
   ```
2. Navigate to the project directory:
   ```bash
   cd network-recon-tool
   ```
3. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the application:
   ```bash
   python network_recon.py
   ```
2. Enter the IP network and network bits in the input fields.
3. Click the "Scan" button to start the network scan.
4. Wait for the scanning progress to complete.
5. View the discovered devices' information in the text area.

## Acknowledgments
- The Network Reconnaissance Tool is built using Python, Tkinter, and Scapy.

