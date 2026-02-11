# NetRunner OS v2

NetRunner OS is a self-contained web application for network traffic simulation, PCAP replay, and analysis. It is designed to test Network Detection and Response (NDR) solutions by rewriting and transmitting PCAPs.

## Enhancements in v2

This version is a major refactor of the original script, transforming it into a modular Flask application with significant UI/UX improvements.

### Key Features

*   **Modular Architecture**: Split into a proper Flask project structure for better maintainability and scalability.
*   **Enhanced Packet Viewer**:
    *   **Wireshark-like Interface**: Split-pane view with a packet list on top and detailed layer decoding on the bottom.
    *   **Deep Inspection**: Decodes Ethernet, IP, TCP, UDP, ICMP, and Payload layers.
    *   **Hex Dump**: Preview payload data in hex format.
*   **Smart Rewriting**:
    *   **Context Menu**: Right-click on any packet in the viewer to instantly add its Source/Destination IP or MAC to the rewrite rules.
    *   **Visual Feedback**: Selected packets are highlighted.
*   **Improved UI/UX**:
    *   Refined "Cyberpunk" aesthetic with better CSS organization.
    *   Responsive layouts and sticky table headers.
    *   Real-time status updates and charts.

## Project Structure

```
netrunner/
├── app/
│   ├── __init__.py      # App factory
│   ├── routes.py        # API endpoints and route logic
│   ├── core/
│   │   ├── engine.py    # Traffic generation and replay logic (Scapy)
│   │   └── database.py  # SQLite database management
│   ├── templates/
│   │   └── index.html   # Main frontend template
│   └── static/
│       ├── css/
│       │   └── style.css # Custom styles
│       └── js/
│           └── main.js   # Frontend logic
├── run.py               # Entry point
├── requirements.txt     # Python dependencies
└── netrunner-v1.py      # (Original backup)
```

## Installation & Usage

1.  **Prerequisites**: Ensure Python 3 and `pip` are installed. You may need `libpcap` headers for Scapy (usually pre-installed on Mac/Linux).

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Application**:
    ```bash
    sudo python3 run.py
    ```
    *Note: `sudo` is required for sending packets via Scapy.*

4.  **Access the Interface**:
    Open your browser and navigate to: `http://127.0.0.1:9000`

## Workflow

1.  **Upload & Analyze**: Go to the **PCAP Replayer** tab and upload a `.pcap` file. The **Packet Viewer** will automatically populate with detailed packet info.
2.  **Select & Rewrite**: Use the **Packet Viewer** to inspect traffic. Right-click a packet to add its IP/MAC to the rewrite maps.
3.  **Configure**: Adjust replay speed, loop settings, and manual rewrite rules.
4.  **Replay**: Click "Initiate Replay" to stream the modified traffic to the target interface.
