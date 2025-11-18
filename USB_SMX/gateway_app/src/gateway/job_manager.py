# Manages the lifecycle of processing jobs.
import os
import uuid
import json
import tempfile
import datetime
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field

# For the MVP, store jobs in a local directory for easy access.
# In a production scenario, this would be a more robust location like ProgramData.
JOB_ROOT_DIR = Path(__file__).parent.parent.parent / "jobs"

class JobState(Enum):
    """Enumeration of all possible job states."""
    INITIALIZED = "INITIALIZED"
    ENUMERATING = "ENUMERATING"
    POLICY_CHECK = "POLICY_CHECK"
    SCANNING = "SCANNING"
    PACKAGING = "PACKAGING"
    SUCCESS = "SUCCESS"
    FAILED_POLICY = "FAILED_POLICY"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"

@dataclass
class Job:
    """Represents a single processing job."""
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    state: JobState = JobState.INITIALIZED
    _path: Path = field(default=None, init=False)
    
    @property
    def path(self) -> Path:
        """The directory where the job's data is stored."""
        if self._path is None:
            return JOB_ROOT_DIR / self.job_id
        return self._path
    
    @path.setter
    def path(self, value: Path):
        """Set the job path (for testing purposes)."""
        self._path = value

class JobManager:
    """Handles the creation and state management of jobs."""
    def __init__(self, gui_queue=None):
        self.gui_queue = gui_queue
        # Ensure the root job directory exists.
        JOB_ROOT_DIR.mkdir(parents=True, exist_ok=True)

    def initialize_job(self, device_metadata: dict) -> Job | None:
        """
        Creates a new job, including its directory structure and initial files.
        """
        job = Job()
        print(f"Initializing job {job.job_id}...")
        
        try:
            job.path.mkdir(parents=True, exist_ok=False)
            
            self._write_json_atomically(job.path / "metadata.json", device_metadata)
            
            # Create an empty log file before the first log event.
            (job.path / "logs.jsonl").touch()
            
            self.update_state(job, JobState.INITIALIZED, {"detail": "Job created and metadata saved."})
            
            print(f"Job {job.job_id} initialized successfully at {job.path}")
            return job
            
        except FileExistsError:
            print(f"Error: Job directory {job.path} already exists.")
            return None
        except Exception as e:
            print(f"Failed to initialize job {job.job_id}: {e}")
            return None

    def update_state(self, job: Job, new_state: JobState, log_details: dict = None):
        """
        Atomically updates the state of the job and logs the transition.
        """
        job.state = new_state
        
        # Log the state transition event
        log_message = f"State changed to {new_state.value}"
        self.log_event(job, "STATE_TRANSITION", {"new_state": new_state.value, "details": log_details or {}})

        # Update the state.json file
        try:
            # Read existing history if it exists
            state_data = self._read_json(job.path / "state.json")
            history = state_data.get("history", [])
        except FileNotFoundError:
            history = []

        history.append({
            "state": new_state.value,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
        })

        state_payload = {
            "current_state": new_state.value,
            "history": history
        }
        self._write_json_atomically(job.path / "state.json", state_payload)

        # Send update to GUI if queue exists
        if self.gui_queue:
            self.gui_queue.put({
                "event": "STATE_UPDATE",
                "job_id": job.job_id,
                "state": new_state.value
            })

    def log_event(self, job: Job, event_type: str, data: dict):
        """
        Appends a structured event to the job's logs.jsonl file.
        """
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "data": data
        }
        try:
            with open(job.path / "logs.jsonl", 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Warning: Failed to write to log for job {job.job_id}: {e}")

        # Send update to GUI if queue exists
        if self.gui_queue:
            log_message = f"[{timestamp}] {event_type}: {json.dumps(data)}"
            self.gui_queue.put({
                "event": "LOG_EVENT",
                "job_id": job.job_id,
                "log_message": log_message
            })

    def _write_json_atomically(self, file_path: Path, data: dict):
        """
        Writes a dictionary to a JSON file atomically.
        """
        fd, tmp_path_str = tempfile.mkstemp(dir=file_path.parent)
        tmp_path = Path(tmp_path_str)
        
        try:
            with os.fdopen(fd, 'w') as tmp_file:
                json.dump(data, tmp_file, indent=4)
            tmp_path.replace(file_path)
        except Exception as e:
            print(f"Failed to write to {file_path} atomically: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            raise

    def _read_json(self, file_path: Path) -> dict:
        """Reads a JSON file."""
        with open(file_path, 'r') as f:
            return json.load(f)