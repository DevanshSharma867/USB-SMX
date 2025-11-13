import unittest
from unittest.mock import patch, MagicMock
import sys
import tempfile
import shutil
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

# Mock Windows-specific modules
sys.modules['wmi'] = MagicMock()
sys.modules['pythoncom'] = MagicMock()

from gateway.device_manager import DeviceManager
from gateway.job_manager import JobState, Job

class TestScannerEndToEnd(unittest.TestCase):
    """End-to-end tests for the malware scanner."""

    def setUp(self):
        """Set up a temporary directory to simulate a USB drive."""
        self.temp_dir = tempfile.mkdtemp()
        self.usb_path = Path(self.temp_dir)
        self.jobs_path = self.usb_path / "jobs"
        self.jobs_path.mkdir()

    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.temp_dir)

    @patch('gateway.file_processor.os.walk')
    @patch('gateway.job_manager.JOB_ROOT_DIR')
    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    @patch('gateway.device_manager.FileProcessor')
    @patch('gateway.device_manager.JobManager')
    def test_malware_detection_and_quarantine(self, mock_job_manager, mock_file_processor, mock_collect_metadata, mock_job_root_dir, mock_os_walk):
        """Test that a device with a malicious file is quarantined."""
        # 1. Create a dummy malicious file on the simulated USB drive
        malicious_file = self.usb_path / "eicar.com"
        malicious_file.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

        # 2. Setup mocks
        mock_collect_metadata.return_value = {"device_serial": "MALICIOUS_USB"}
        mock_job_root_dir.return_value = self.jobs_path
        mock_os_walk.return_value = [
            (str(self.usb_path), [], ["eicar.com"]),
        ]
        
        job = Job()
        job.job_id = "test_job"
        mock_job_manager.return_value.initialize_job.return_value = job
        
        # Mock FileProcessor to simulate malware detection
        mock_file_processor_instance = mock_file_processor.return_value
        mock_file_processor_instance.process_device.side_effect = lambda job, root_path, drive_letter: mock_job_manager.return_value.update_state(job, JobState.QUARANTINED, {"file": "eicar.com", "threat": "EICAR test file"})
        
        device_manager = DeviceManager()
        device_manager._job_manager = mock_job_manager.return_value

        # 3. Process the device
        device_manager._handle_device_insertion(str(self.usb_path))

        # 4. Assert that the job was quarantined
        mock_job_manager.return_value.update_state.assert_any_call(job, JobState.QUARANTINED, unittest.mock.ANY)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    @patch('gateway.device_manager.FileProcessor')
    @patch('gateway.device_manager.JobManager')
    def test_clean_file_processing(self, mock_job_manager, mock_file_processor, mock_collect_metadata, mock_job_root_dir):
        """Test that a device with clean files is processed successfully."""
        # 1. Create a dummy clean file on the simulated USB drive
        clean_file = self.usb_path / "clean.txt"
        clean_file.write_text("This is a clean file.")

        # 2. Setup mocks
        mock_collect_metadata.return_value = {"device_serial": "CLEAN_USB"}
        mock_job_root_dir.return_value = self.jobs_path
        
        job = Job()
        job.job_id = "test_job"
        mock_job_manager.return_value.initialize_job.return_value = job
        
        # Mock FileProcessor to simulate successful processing
        mock_file_processor_instance = mock_file_processor.return_value
        mock_file_processor_instance.process_device.side_effect = lambda job, root_path, drive_letter: mock_job_manager.return_value.update_state(job, JobState.SUCCESS, {"detail": "Job completed successfully. 1 files processed."})
        
        device_manager = DeviceManager()
        device_manager._job_manager = mock_job_manager.return_value

        # 3. Process the device
        device_manager._handle_device_insertion(str(self.usb_path))

        # 4. Assert that the job was successful
        mock_job_manager.return_value.update_state.assert_any_call(job, JobState.SUCCESS, unittest.mock.ANY)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    @patch('gateway.file_processor.subprocess.run')
    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    @patch('gateway.device_manager.FileProcessor')
    @patch('gateway.device_manager.JobManager')
    def test_scanner_error_handling(self, mock_job_manager, mock_file_processor, mock_collect_metadata, mock_subprocess_run, mock_job_root_dir):
        """Test that the job fails if the scanner returns an error."""
        # 1. Create a dummy file on the simulated USB drive
        some_file = self.usb_path / "some_file.txt"
        some_file.write_text("This is a file that will cause a scanner error.")

        # 2. Setup mocks
        mock_collect_metadata.return_value = {"device_serial": "ERROR_USB"}
        mock_subprocess_run.side_effect = Exception("Scanner crashed")
        mock_job_root_dir.return_value = self.jobs_path
        
        job = Job()
        job.job_id = "test_job"
        mock_job_manager.return_value.initialize_job.return_value = job
        
        # Mock FileProcessor to simulate scanner error
        mock_file_processor_instance = mock_file_processor.return_value
        mock_file_processor_instance.process_device.side_effect = lambda job, root_path, drive_letter: mock_job_manager.return_value.update_state(job, JobState.FAILED, {"error": "Scanner crashed"})
        
        device_manager = DeviceManager()
        device_manager._job_manager = mock_job_manager.return_value

        # 3. Process the device
        device_manager._handle_device_insertion(str(self.usb_path))

        # 4. Assert that the job failed
        mock_job_manager.return_value.update_state.assert_any_call(job, JobState.FAILED, unittest.mock.ANY)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    @patch('gateway.device_manager.FileProcessor')
    @patch('gateway.device_manager.JobManager')
    def test_policy_violation_handling(self, mock_job_manager, mock_file_processor, mock_collect_metadata, mock_job_root_dir):
        """Test that a device with policy-violating files is rejected."""
        # 1. Create a file with blacklisted extension
        exe_file = self.usb_path / "malware.exe"
        exe_file.write_text("This is an executable file.")

        # 2. Setup mocks
        mock_collect_metadata.return_value = {"device_serial": "POLICY_VIOLATION_USB"}
        mock_job_root_dir.return_value = self.jobs_path
        
        job = Job()
        job.job_id = "test_job"
        mock_job_manager.return_value.initialize_job.return_value = job
        
        # Mock FileProcessor to simulate policy violation
        mock_file_processor_instance = mock_file_processor.return_value
        mock_file_processor_instance.process_device.side_effect = lambda job, root_path, drive_letter: mock_job_manager.return_value.update_state(job, JobState.FAILED_POLICY, {"policy_id": "fileExtensionBlacklist", "file_path": "malware.exe", "reason": "File extension '.exe' is blacklisted."})
        
        device_manager = DeviceManager()
        device_manager._job_manager = mock_job_manager.return_value

        # 3. Process the device
        device_manager._handle_device_insertion(str(self.usb_path))

        # 4. Assert that the job failed due to policy violation
        mock_job_manager.return_value.update_state.assert_any_call(job, JobState.FAILED_POLICY, unittest.mock.ANY)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    @patch('gateway.device_manager.FileProcessor')
    @patch('gateway.device_manager.JobManager')
    def test_empty_device_processing(self, mock_job_manager, mock_file_processor, mock_collect_metadata, mock_job_root_dir):
        """Test that an empty device is processed successfully."""
        # 1. Create an empty directory (no files)
        
        # 2. Setup mocks
        mock_collect_metadata.return_value = {"device_serial": "EMPTY_USB"}
        mock_job_root_dir.return_value = self.jobs_path
        
        job = Job()
        job.job_id = "test_job"
        mock_job_manager.return_value.initialize_job.return_value = job
        
        # Mock FileProcessor to simulate successful processing of empty device
        mock_file_processor_instance = mock_file_processor.return_value
        mock_file_processor_instance.process_device.side_effect = lambda job, root_path, drive_letter: mock_job_manager.return_value.update_state(job, JobState.SUCCESS, {"detail": "Job completed successfully. 0 files processed."})
        
        device_manager = DeviceManager()
        device_manager._job_manager = mock_job_manager.return_value

        # 3. Process the device
        device_manager._handle_device_insertion(str(self.usb_path))

        # 4. Assert that the job was successful
        mock_job_manager.return_value.update_state.assert_any_call(job, JobState.SUCCESS, unittest.mock.ANY)

if __name__ == '__main__':
    unittest.main()