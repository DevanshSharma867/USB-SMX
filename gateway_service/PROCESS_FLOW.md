# Gateway Service Process Flow

## 1. High-Level Overview

The Gateway Service is a Python application designed to securely process files from removable USB devices. It runs as a background service that automatically detects USB insertions, processes the files according to a configurable set of policies, and generates a secure, encrypted package of the clean files.

The application features a real-time graphical user interface (GUI) that automatically pops up for each device, showing the live status and logs of the processing job. The GUI closes automatically when the device is removed.

---

## 2. Core Components

The application is broken down into several key modules, each with a distinct responsibility.

### `main.py`
- **Role:** Application Entry Point.
- **Function:** This is the script you run to start the service. Its primary job is to initialize and connect all other core components.
- **Process:**
  1. Creates a message `queue` for safe communication between the background threads and the main GUI thread.
  2. Initializes the `GuiManager`, which controls the user interface.
  3. Initializes the `DeviceManager`, which handles hardware detection.
  4. Starts the `DeviceManager`'s background monitoring thread.
  5. Starts the `GuiManager`'s main loop, which makes the application wait for events (both user events and messages on the queue).

### `device_manager.py`
- **Role:** Hardware Interaction Layer.
- **Function:** Detects USB device insertions and removals and manages the top-level workflow for each device.
- **Process:**
  1. Runs a continuous background thread (`_monitor_devices`) that polls the system for changes in connected storage volumes.
  2. **On Insertion:** When a new device is detected, it spawns a new thread (`_handle_device_insertion`) to:
     - Collect detailed metadata about the device (serial number, capacity, etc.).
     - Call the `JobManager` to create a new, persistent job on disk.
     - Place a `NEW_JOB` message on the GUI queue, triggering the pop-up window.
     - Delegate the file processing task to the `FileProcessor`.
  3. **On Removal:** When a device is removed, it calls `_handle_device_removal`, which finds the job associated with that device and places a `DEVICE_REMOVED` message on the GUI queue, triggering the window to close.

### `job_manager.py`
- **Role:** Data Persistence and State Management.
- **Function:** Manages the lifecycle of a processing job on the filesystem. It ensures that all data is stored in an organized way and that state transitions are logged.
- **Process:**
  1. When `initialize_job` is called, it creates a unique directory for the job in the `jobs/` folder.
  2. It creates the three core files: `metadata.json`, `state.json`, and `logs.jsonl`.
  3. Its `update_state` and `log_event` methods provide a centralized way to atomically update the job's status on disk while also sending real-time copies of these events to the GUI queue.

### `file_processor.py`
- **Role:** Core Processing Engine.
- **Function:** Contains the primary business logic. It orchestrates the step-by-step pipeline that files are put through.
- **Process:** Its main method, `process_device`, executes the following sequence:
  1. **Load Policies:** Reads the rules from `policy.json`.
  2. **Enumerate:** Lists all files on the device.
  3. **Policy Check:** Checks the files against the loaded policies (e.g., blacklisted extensions, file size).
  4. **Scan:** Scans the files for threats (currently simulated).
  5. **Package:** If all checks pass, it encrypts the clean files and generates the final `manifest.json`.
  6. Throughout this process, it constantly calls the `JobManager` to update the job's state and log events.

### `crypto.py`
- **Role:** Cryptography Utility.
- **Function:** A helper module that provides all cryptographic functions.
- **Process:** It is used by the `FileProcessor` to:
  - Generate a secure Content Encryption Key (CEK) for each job.
  - Encrypt individual files using the AES-256-GCM algorithm.
  - Calculate SHA-256 hashes.

### `gui.py`
- **Role:** User Interface Layer.
- **Function:** Manages all aspects of the GUI using the Tkinter library. It is completely decoupled from the backend logic.
- **Process:**
  1. The `GuiManager` runs in the main application thread and continuously checks the message queue for new events.
  2. On a `NEW_JOB` event, it creates and displays a new `JobInfoWindow` pop-up.
  3. On `STATE_UPDATE` and `LOG_EVENT` events, it finds the correct window by its Job ID and updates its status label, progress bar, and log box.
  4. On a `DEVICE_REMOVED` event, it finds the corresponding window and closes it.

### `policy.json`
- **Role:** Policy Configuration File.
- **Function:** A simple JSON file that allows an administrator to define and configure the rules for the policy engine without modifying any code. It supports enabling/disabling policies and changing their parameters.

---

## 3. End-to-End Workflow Example

1.  **Startup:** The user runs `python src/gateway/main.py`. The application starts, the device monitor begins running in the background, and the main thread waits for GUI events. No windows are visible.
2.  **Device Insertion:** A user plugs in a USB drive (e.g., `E:`).
3.  **Detection & Job Creation:** The `DeviceManager` detects `E:`, collects its metadata, and tells the `JobManager` to create a job directory (e.g., `jobs/b906af11...`).
4.  **GUI Popup:** The `DeviceManager` sends a `NEW_JOB` message to the queue. The `GuiManager` receives it and a new status window for that job appears on the screen.
5.  **Processing Pipeline:** The `FileProcessor` starts its work. It updates the state to `ENUMERATING`. The `JobManager` writes this to `state.json` and also sends a `STATE_UPDATE` message to the queue.
6.  **Live Updates:** The `GuiManager` receives the `STATE_UPDATE` message. The status label in the pop-up window instantly changes to "ENUMERATING", its color becomes blue, and the progress bar moves. This repeats for every log event and state change (`POLICY_CHECK`, `SCANNING`, etc.).
7.  **Job Completion:** The job finishes with a `SUCCESS` or `FAILED` state. The progress bar fills to 100%, the status color changes to green or red, and the "Open Job Folder" button becomes enabled.
8.  **Device Removal:** The user unplugs the USB drive.
9.  **GUI Cleanup:** The `DeviceManager` detects the removal, finds the job associated with that drive, and sends a `DEVICE_REMOVED` message. The `GuiManager` receives it and automatically closes the corresponding pop-up window.

---

## 4. Data Storage Structure

All persistent data generated by the application is stored within the `jobs/` directory, located at the root of the project.

```
gateway_service/
└── jobs/
    └── <job_id>/                  <-- A unique directory for each processing job
        ├── metadata.json          <-- Static metadata about the source device (serial, capacity, etc.)
        ├── state.json             <-- The current state of the job and a history of all past states.
        ├── logs.jsonl             <-- A detailed, append-only log of every event during the job.
        └── manifest.json          <-- The final report listing all processed files and their cryptographic details.

<Pendrive Root>/
└── .gateway_output/               <-- Hidden folder created on the pendrive
    ├── cek.key                    <-- The encryption key for this job's files (insecurely stored for MVP).
    └── data/                      <-- A subdirectory containing the encrypted file blobs.
        ├── <file_hash_1>
        └── <file_hash_2>
```