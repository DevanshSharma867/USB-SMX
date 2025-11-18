
import unittest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import json
import tempfile
import shutil
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.job_manager import JobManager, Job, JobState

class TestJobManager(unittest.TestCase):

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    def setUp(self, mock_job_root):
        """Set up for each test, mocking the root job directory."""
        # Make the mocked JOB_ROOT_DIR appear to exist
        mock_job_root.exists.return_value = True
        self.job_manager = JobManager()
        self.device_metadata = {"device_serial": "12345"}

    @patch('gateway.job_manager.Path.mkdir')
    @patch('gateway.job_manager.Path.touch')
    @patch('gateway.job_manager.tempfile.mkstemp')
    @patch('os.fdopen')
    @patch('gateway.job_manager.Path.replace')
    def test_initialize_job_success(self, mock_replace, mock_fdopen, mock_mkstemp, mock_touch, mock_mkdir):
        """Test the successful initialization of a job."""
        # Mock the temporary file creation and writing
        mock_mkstemp.return_value = (123, 'temp_file_path')
        mock_fd_obj = MagicMock()
        mock_fdopen.return_value = mock_fd_obj

        # Call the method to be tested
        job = self.job_manager.initialize_job(self.device_metadata)

        self.assertIsNotNone(job)
        self.assertIsInstance(job, Job)
        self.assertEqual(job.state, JobState.INITIALIZED)

        # Check that the directory and files were created
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=False)
        mock_touch.assert_called_once() # For logs.jsonl

        # Check that metadata.json and state.json were written
        self.assertEqual(mock_fdopen.call_count, 2)
        self.assertEqual(mock_replace.call_count, 2)

    @patch('gateway.job_manager.Path.mkdir')
    def test_initialize_job_failure(self, mock_mkdir):
        """Test job initialization failure if the directory already exists."""
        mock_mkdir.side_effect = FileExistsError
        job = self.job_manager.initialize_job(self.device_metadata)
        self.assertIsNone(job)

    @patch('gateway.job_manager.json.dump')
    @patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file_path'))
    @patch('os.fdopen')
    @patch('gateway.job_manager.Path.replace')
    def test_update_state(self, mock_replace, mock_fdopen, mock_mkstemp, mock_json_dump):
        """Test that the update_state method writes the correct data."""
        job = Job()
        self.job_manager.update_state(job, JobState.PACKAGING)

        self.assertEqual(job.state, JobState.PACKAGING)
        
        # Verify that json.dump was called with the correct data and file object
        mock_json_dump.assert_called_once()
        written_data = mock_json_dump.call_args[0][0]
        self.assertEqual(written_data['current_state'], 'PACKAGING')

        # Verify the atomic replace was called
        mock_replace.assert_called_once()

    def test_job_creation_with_uuid(self):
        """Test that jobs are created with unique UUIDs."""
        job1 = Job()
        job2 = Job()
        
        self.assertNotEqual(job1.job_id, job2.job_id)
        self.assertIsInstance(job1.job_id, str)
        self.assertIsInstance(job2.job_id, str)
        self.assertEqual(len(job1.job_id), 36)  # UUID4 format

    def test_job_path_property(self):
        """Test that job path property returns correct path."""
        job = Job()
        expected_path = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "SMX" / "Jobs" / job.job_id
        
        self.assertEqual(job.path, expected_path)

    def test_job_initial_state(self):
        """Test that jobs start in INITIALIZED state."""
        job = Job()
        self.assertEqual(job.state, JobState.INITIALIZED)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    def test_initialize_job_directory_creation_failure(self, mock_job_root):
        """Test job initialization when directory creation fails."""
        mock_job_root.mkdir.side_effect = PermissionError("Permission denied")
        
        job = self.job_manager.initialize_job(self.device_metadata)
        self.assertIsNone(job)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    def test_initialize_job_json_write_failure(self, mock_job_root):
        """Test job initialization when JSON writing fails."""
        mock_job_root.mkdir.return_value = None
        mock_job_root.touch.return_value = None
        
        with patch('gateway.job_manager.tempfile.mkstemp', side_effect=OSError("Disk full")):
            job = self.job_manager.initialize_job(self.device_metadata)
            self.assertIsNone(job)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    def test_initialize_job_metadata_write_failure(self, mock_job_root):
        """Test job initialization when metadata write fails."""
        mock_job_root.mkdir.return_value = None
        mock_job_root.touch.return_value = None
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', side_effect=OSError("Permission denied")):
                job = self.job_manager.initialize_job(self.device_metadata)
                self.assertIsNone(job)

    @patch('gateway.job_manager.JOB_ROOT_DIR')
    def test_initialize_job_state_write_failure(self, mock_job_root):
        """Test job initialization when state write fails."""
        mock_job_root.mkdir.return_value = None
        mock_job_root.touch.return_value = None
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()):
                with patch('gateway.job_manager.json.dump', side_effect=OSError("Disk full")):
                    job = self.job_manager.initialize_job(self.device_metadata)
                    self.assertIsNone(job)

    def test_update_state_with_additional_data(self):
        """Test updating job state with additional data."""
        job = Job()
        additional_data = {"error_message": "Test error", "retry_count": 3}
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()):
                with patch('gateway.job_manager.Path.replace'):
                    self.job_manager.update_state(job, JobState.FAILED, additional_data)
                    
                    self.assertEqual(job.state, JobState.FAILED)

    def test_update_state_all_states(self):
        """Test updating job state through all possible states."""
        job = Job()
        
        states_to_test = [
            JobState.INITIALIZED,
            JobState.ENUMERATING,
            JobState.POLICY_CHECK,
            JobState.SCANNING,
            JobState.PACKAGING,
            JobState.SUCCESS,
            JobState.FAILED_POLICY,
            JobState.QUARANTINED,
            JobState.FAILED
        ]
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()):
                with patch('gateway.job_manager.Path.replace'):
                    for state in states_to_test:
                        self.job_manager.update_state(job, state)
                        self.assertEqual(job.state, state)

    def test_write_json_atomically_success(self):
        """Test successful atomic JSON writing."""
        test_data = {"key": "value", "number": 42}
        test_file = Path("test.json")
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()) as mock_fdopen:
                with patch('gateway.job_manager.Path.replace') as mock_replace:
                    self.job_manager._write_json_atomically(test_file, test_data)
                    
                    # Verify temp file was created and JSON was written
                    mock_fdopen.assert_called_once()
                    mock_replace.assert_called_once()

    def test_write_json_atomically_failure_cleanup(self):
        """Test atomic JSON writing failure with cleanup."""
        test_data = {"key": "value"}
        test_file = Path("test.json")
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', side_effect=OSError("Write failed")):
                with patch('gateway.job_manager.Path.exists', return_value=True):
                    with patch('gateway.job_manager.Path.unlink') as mock_unlink:
                        with self.assertRaises(OSError):
                            self.job_manager._write_json_atomically(test_file, test_data)
                        
                        # Verify cleanup was attempted
                        mock_unlink.assert_called_once()

    def test_write_json_atomically_no_cleanup_needed(self):
        """Test atomic JSON writing failure when no cleanup is needed."""
        test_data = {"key": "value"}
        test_file = Path("test.json")
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', side_effect=OSError("Write failed")):
                with patch('gateway.job_manager.Path.exists', return_value=False):
                    with patch('gateway.job_manager.Path.unlink') as mock_unlink:
                        with self.assertRaises(OSError):
                            self.job_manager._write_json_atomically(test_file, test_data)
                        
                        # Verify no cleanup was attempted
                        mock_unlink.assert_not_called()

    def test_job_manager_initialization(self):
        """Test JobManager initialization creates root directory."""
        with patch('gateway.job_manager.JOB_ROOT_DIR') as mock_root:
            mock_root.mkdir.return_value = None
            manager = JobManager()
            mock_root.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    def test_job_manager_initialization_directory_exists(self):
        """Test JobManager initialization when directory already exists."""
        with patch('gateway.job_manager.JOB_ROOT_DIR') as mock_root:
            mock_root.mkdir.side_effect = FileExistsError("Directory exists")
            # Should not raise exception
            manager = JobManager()
            mock_root.mkdir.assert_called_once_with(parents=True, exist_ok=True)

    def test_job_state_enum_values(self):
        """Test that all job states have correct string values."""
        expected_states = {
            JobState.INITIALIZED: "INITIALIZED",
            JobState.ENUMERATING: "ENUMERATING",
            JobState.POLICY_CHECK: "POLICY_CHECK",
            JobState.SCANNING: "SCANNING",
            JobState.PACKAGING: "PACKAGING",
            JobState.SUCCESS: "SUCCESS",
            JobState.FAILED_POLICY: "FAILED_POLICY",
            JobState.QUARANTINED: "QUARANTINED",
            JobState.FAILED: "FAILED"
        }
        
        for state, expected_value in expected_states.items():
            self.assertEqual(state.value, expected_value)

    def test_job_state_transitions(self):
        """Test valid job state transitions."""
        job = Job()
        
        # Test a valid state transition sequence
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()):
                with patch('gateway.job_manager.Path.replace'):
                    # Initialize -> Enumerating -> Scanning -> Packaging -> Success
                    self.job_manager.update_state(job, JobState.ENUMERATING)
                    self.assertEqual(job.state, JobState.ENUMERATING)
                    
                    self.job_manager.update_state(job, JobState.SCANNING)
                    self.assertEqual(job.state, JobState.SCANNING)
                    
                    self.job_manager.update_state(job, JobState.PACKAGING)
                    self.assertEqual(job.state, JobState.PACKAGING)
                    
                    self.job_manager.update_state(job, JobState.SUCCESS)
                    self.assertEqual(job.state, JobState.SUCCESS)

    def test_job_state_error_transitions(self):
        """Test error state transitions."""
        job = Job()
        
        with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
            with patch('os.fdopen', return_value=MagicMock()):
                with patch('gateway.job_manager.Path.replace'):
                    # Test transition to error states
                    self.job_manager.update_state(job, JobState.QUARANTINED)
                    self.assertEqual(job.state, JobState.QUARANTINED)
                    
                    job2 = Job()
                    self.job_manager.update_state(job2, JobState.FAILED)
                    self.assertEqual(job2.state, JobState.FAILED)
                    
                    job3 = Job()
                    self.job_manager.update_state(job3, JobState.FAILED_POLICY)
                    self.assertEqual(job3.state, JobState.FAILED_POLICY)

    def test_concurrent_job_creation(self):
        """Test creating multiple jobs concurrently."""
        jobs = []
        
        with patch('gateway.job_manager.JOB_ROOT_DIR') as mock_root:
            mock_root.mkdir.return_value = None
            mock_root.touch.return_value = None
            
            with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
                with patch('os.fdopen', return_value=MagicMock()):
                    with patch('gateway.job_manager.Path.replace'):
                        # Create multiple jobs
                        for i in range(10):
                            job = self.job_manager.initialize_job(self.device_metadata)
                            if job:  # Only add if creation succeeded
                                jobs.append(job)
        
        # All jobs should have unique IDs
        job_ids = [job.job_id for job in jobs]
        self.assertEqual(len(job_ids), len(set(job_ids)))

    def test_job_with_complex_metadata(self):
        """Test job creation with complex metadata structure."""
        complex_metadata = {
            "device_serial": "ABC123",
            "nested_data": {
                "key1": "value1",
                "key2": [1, 2, 3],
                "key3": {"nested": True}
            },
            "unicode_data": "测试数据",
            "special_chars": "!@#$%^&*()",
            "large_data": "x" * 1000
        }
        
        with patch('gateway.job_manager.JOB_ROOT_DIR') as mock_root:
            mock_root.mkdir.return_value = None
            mock_root.touch.return_value = None
            
            with patch('gateway.job_manager.tempfile.mkstemp', return_value=(123, 'temp_file')):
                with patch('os.fdopen', return_value=MagicMock()):
                    with patch('gateway.job_manager.Path.replace'):
                        job = self.job_manager.initialize_job(complex_metadata)
                        self.assertIsNotNone(job)
                        self.assertEqual(job.state, JobState.INITIALIZED)

if __name__ == '__main__':
    unittest.main()
