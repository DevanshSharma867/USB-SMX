# USB SMX Project

A secure data transfer and management system.

## Overview

This project consists of three main components:

*   **Gateway App**: A central service for managing devices, processing files, and handling encryption.
*   **Agent App**: An agent application that runs on client devices to decrypt and process data.
*   **KMS Server**: A Key Management Service for securely storing and managing cryptographic keys.

## Project Structure

```
USB_SMX_MVP/
├── gateway_service/
│   └── ...
├── USB_SMX/
│   ├── agent_app/
│   │   ├── src/
│   │   │   ├── agent_crypto.py
│   │   │   ├── agent_device_manager.py
│   │   │   ├── agent_file_processor.py
│   │   │   ├── agent_gui.py
│   │   │   └── agent_main.py
│   │   └── tests/
│   │       └── test_agent.py
│   ├── gateway_app/
│   │   ├── src/
│   │   │   └── gateway/
│   │   │       ├── crypto.py
│   │   │       ├── device_manager.py
│   │   │       ├── file_processor.py
│   │   │       ├── gui.py
│   │   │       ├── job_manager.py
│   │   │       ├── kms.py
│   │   │       └── main.py
│   │   └── tests/
│   │       ├── test_crypto.py
│   │       ├── test_device_manager.py
│   │       ├── test_file_processor.py
│   │       └── test_job_manager.py
│   └── kms_server/
│       ├── main.py
│       └── requirements.txt
├── .gitignore
└── README.md
```

## Features

*   **Gateway App**:
    *   Secure file encryption and decryption.
    *   Device management and communication.
    *   Job processing and management.
    *   File processing capabilities.
    *   Graphical user interface.
*   **Agent App**:
    *   Decrypts and processes data on client devices.
    *   Communicates with the Gateway App.
*   **KMS Server**:
    *   Securely stores and manages cryptographic keys.
    *   Provides keys to the Gateway App on demand.

## Requirements

See the `requirements.txt` file in each component's directory for detailed Python package dependencies.

## Installation

### Gateway App

1.  Navigate to the `USB_SMX/gateway_app` directory.
2.  Install required dependencies:
    ```bash
    pip install -r src/requirements.txt
    ```

### Agent App

1.  Navigate to the `USB_SMX/agent_app` directory.
2.  Install required dependencies:
    ```bash
    pip install -r src/requirements.txt
    ```

### KMS Server

1.  Navigate to the `USB_SMX/kms_server` directory.
2.  Install required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Gateway App

To start the Gateway App:

```bash
python USB_SMX/gateway_app/src/gateway/main.py
```

### Agent App

To start the Agent App:

```bash
python USB_SMX/agent_app/src/agent_main.py
```

### KMS Server

To start the KMS Server:

```bash
python USB_SMX/kms_server/main.py
```

## Testing

### Gateway App

Run the test suite using:

```bash
pytest USB_SMX/gateway_app/tests/
```

### Agent App

Run the test suite using:

```bash
pytest USB_SMX/agent_app/tests/
```

## Contact

-   Developer: Devansh Sharma
-   Repository: [USB-SMX---Gateway-Portal](https://github.com/DevanshSharma867/USB-SMX---Gateway-Portal)
