# LightIDS_NET

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

LightIDS_NET is a lightweight, real-time network Intrusion Detection System (IDS) implemented in Python. It is designed to monitor network traffic, identify suspicious activities based on a defined set of rules, and log alerts for further analysis.

## Table of Contents

-   [Features](#features)
-   [Prerequisites](#prerequisites)
-   [Installation](#installation)
-   [Usage](#usage)
-   [Roadmap](#roadmap)
-   [Contributing](#contributing)
-   [License](#license)

## Features

-   **Real-time Packet Analysis:** Monitors network traffic using the Scapy library.
-   **Threat Detection:** Identifies common network threats, including port scans and flood/brute-force attempts.
-   **Structured Logging:** Generates detailed alerts in JSON format, capturing timestamps, source/destination IPs, and ports.
-   **Command-Line Interface:** Provides a simple and effective CLI for operation and configuration.

## Prerequisites

To run this software, you will need the following installed on your system:

-   Python 3.8 or later
-   Git
-   Npcap (for Windows users) or an equivalent packet capture library for your OS.

## Installation

Follow these steps to set up the project on your local machine.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/saivenkatkr/LightIDS_NET.git](https://github.com/saivenkatkr/LightIDS_NET.git)
    cd LightIDS_NET
    ```

2.  **Create a Virtual Environment (Recommended):**
    It is highly recommended to run the project in a dedicated virtual environment.
    ```bash
    # Using Conda
    conda create -n lightids python=3.10 -y
    conda activate lightids
    ```

3.  **Install Dependencies:**
    Install the required Python packages from the `requirements.txt` file.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

All commands should be executed from the project's root directory.

1.  **List Network Interfaces:**
    To find the name of the network interface you wish to monitor, run the following command:
    ```bash
    python -m src.main --list-ifaces
    ```

2.  **Run the Intrusion Detection System:**
    Start monitoring a specific interface using its name from the list above.
    ```bash
    python -m src.main --iface "Your-Interface-Name" --stats-every 5
    ```
    The system is now active and will log detected threats.

## Roadmap

Future enhancements planned for this project include:

-   [ ] Detection of additional attack vectors (e.g., ARP spoofing).
-   [ ] Integration of a configuration file for dynamic rule updates.
-   [ ] Development of an optional graphical user interface (GUI).

## Contributing

Contributions are welcome. Please open an issue to discuss a change or submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
