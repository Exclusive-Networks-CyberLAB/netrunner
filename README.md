NetRunner OS - Network Simulation Studio

NetRunner OS is a self-contained, single-file Python web application designed for network security professionals, NDR (Network Detection and Response) testers, and hobbyists. It provides a cyberpunk-themed web interface to simulate network traffic for testing and analysis.

The application combines three core tools into a single, unified interface:

A PCAP Replayer: To replay existing packet captures (PCAPs) with complex, on-the-fly rewriting rules.

A Traffic Generator: To craft and send stateless TCP, UDP, or ICMP packets from scratch.

An Intelligent Packet Viewer: To analyze an uploaded PCAP, map IP to MAC addresses, and heuristically identify the potential attacker.

(You should replace the line above with a screenshot of the running application)

Features

Unified Interface

Tabbed Navigation: Seamlessly switch between the PCAP Replayer, Traffic Generator, and Packet Viewer.

Cyberpunk-themed UI: A clean, high-tech interface built for clarity and style, using cyan and magenta accents.

Real-time Monitoring: A shared status panel provides a live-updating graph of packets-per-second, a task progress bar, and a collapsible, verbose console log.

Self-Contained: The entire application (backend and frontend) is contained within a single Python script.

Automatic Dependency Installation: The script checks for and installs required Python libraries (Flask and Scapy) on first run.

PCAP Replayer & Analyzer

Intelligent PCAP Analysis: When a PCAP is uploaded, the app automatically analyzes the first 500 packets to:

Map Hosts: Creates a "Discovered Hosts" table that maps IP addresses to their last-seen MAC address.

Identify Attacker: Uses a heuristic (unique port scanning) to flag the most likely adversary IP in the table, saving you analysis time.

Smart Quick-Add: A + button next to each discovered host lets you add both its IP and MAC to the rewrite rules simultaneously.

Complex Rewriting: On-the-fly rewriting of:

Source/Destination IP Addresses

Source/Destination MAC Addresses

Source/Destination TCP/UDP Ports

Advanced Replay Control:

Speed: Replay at original timing or "as fast as possible" for stress testing.

Looping: Loop the PCAP indefinitely or for a specific number of cycles.

VLAN Tagging: Add or overwrite an 802.1Q VLAN tag on all packets.

TTL Modification: Set a static IP Time-to-Live (TTL) for all replayed packets.

Packet Viewer

Quick Analysis: After uploading a PCAP, this tab populates with a summary of the first 500 packets.

Conversation View: Clearly shows Source, Destination, Protocol, and Info for each packet, helping you quickly identify traffic flows and set up rewrite rules.

Traffic Generator

Stateless Generation: Craft and send stateless TCP, UDP, or ICMP packets.

Full Packet Control: Define all key fields:

Source/Destination IP and MAC

Source/Destination Port (for TCP/UDP)

Custom text payload

Transmission Control: Specify the exact packet count and the delay (in seconds) between each packet.

Global Features

Asset Manager: An in-memory database to save frequently used "Assets" (Name, IP, MAC). These assets can be selected from dropdowns throughout the app to quickly populate fields, saving you from re-typing.

Input Validation: Real-time validation on all IP and MAC address fields to prevent formatting errors.

Installation & Setup

This application is designed to be simple to run.

Clone the repository (or download the script):

git clone <your-repo-url>
cd <your-repo-name>


...or just save the network_simulation_studio_v2.py file to a new directory.

Run the script with administrator privileges:
This tool requires root/administrator privileges to bind to network interfaces and send raw packets.

On macOS / Linux:

sudo python3 network_simulation_studio_v2.py


On Windows:
Open a Command Prompt or PowerShell as Administrator and run:

python network_simulation_studio_v2.py


Automatic Setup: The script will first check if Flask and Scapy are installed. If not, it will attempt to install them using pip.

Access the Application: Once the script is running, it will print the local URL. Open your web browser and navigate to:
http://127.0.0.1:9000

How to Use

⚠️ Security Warning ⚠️

This tool is capable of injecting raw packets onto a network and can easily be used to perform scanning, spoofing, and DoS attacks.

DO NOT run this on a corporate, public, or any network you do not own.

ONLY use this tool in an isolated, controlled lab environment for legitimate testing and analysis.

You are solely responsible for your actions. This tool is provided for educational and testing purposes only.

1. The Asset Manager

The Asset Manager is a global feature at the top of the page.

Enter a Name, IP, and MAC for a device you want to save (e.g., "Test Victim 1", "10.1.1.50", "00:11:22:33:44:55").

Click Add Asset.

This asset will now be available in dropdowns throughout the app to auto-fill fields. This list is in-memory and will be cleared when the app is restarted.

2. PCAP Replayer & Viewer

The Replayer and Viewer tabs work together.

Upload PCAP: On the // PCAP Replayer // tab, click "Choose File" and select a .pcap or .pcapng file.

Analyze (Automatic): The app will immediately show an "Analyzing PCAP..." status. Once complete:

The Discovered Hosts table will appear, mapping IPs to MACs and highlighting the potential adversary.

The // Packet Viewer // tab is now populated.

Review Traffic: Click the // Packet Viewer // tab. You will see a table summarizing the first 500 packets. Use this to confirm the analysis and see the conversations.

Create Rewrite Rules:

Go back to the // PCAP Replayer // tab.

Click the + button next to a discovered host. This will add both an IP and MAC rewrite rule for that host.

You can also add rules manually by clicking + Add IP/MAC/Port Map.

Use the asset dropdowns or type in the "New" fields to define what the original addresses should be rewritten to.

Set Options:

Fill in the Egress Interface (e.g., eth0, en0).

Configure any Advanced Replay Options like looping or replay speed.

Initiate: Click the Initiate Replay button.

3. Traffic Generator Tab

Configure L2/L3:

Fill in the Source/Destination IP and MAC fields. You can use the Asset Manager dropdowns to auto-fill these.

Note: Source MAC is optional and will be auto-detected if left blank.

Configure L4 & Payload:

Select the Protocol (TCP, UDP, or ICMP).

If TCP/UDP, fill in the Source/Destination Ports.

(Optional) Add a text Payload.

Configure Transmission:

Set the Packet Count (how many packets to send).

Set the Delay (time in seconds between packets, e.g., 0.1 for 10 packets/sec).

Set the Interface to send from.

Generate: Click the Generate Traffic button.

4. Monitoring Panel

Once you start a task, the status panel appears at the bottom.

Progress Bar & Status: Shows the real-time progress of the task.

Abort Button: Immediately stops the running task.

Traffic Graph: A live chart showing the number of packets being sent per second.

System Log: A collapsible console that provides a detailed, real-time log of what the application is doing, including setup and any errors.

Dependencies

Python 3.x

Flask: For the web server and UI.

Scapy: For all packet crafting, analysis, and sending.

These are installed automatically by the script.

License

This project is unlicensed. You are free to fork, modify, share, and use this code however you see fit.