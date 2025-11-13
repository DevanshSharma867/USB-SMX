#!/usr/bin/env python
"""
Unit tests for the FileProcessor module.

This test suite is designed to test the refactored FileProcessor, where logic
is split into discrete units for enumeration, policy checking, scanning, and packaging.
"""

import unittest
from unittest.mock import patch, MagicMock, call, mock_open, ANY
import sys
import json
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.file_processor import FileProcessor
from gateway.job_manager import Job, JobState

class TestFileProcessor(unittest.TestCase):

    def setUp(self):
        """Set up a mock JobManager for each test."""
        self.mock_job_manager = MagicMock()

    # ===== Test Policy Loading (_load_policies) =====

    @patch("builtins.open", new_callable=mock_open, read_data=json.dumps({
        "policies": [
            {"id": "P01", "enabled": True, "type": "type1"},
            {"id": "P02", "enabled": False, "type": "type2"},
            {"id": "P03", "enabled": True, "type": "type3"}
        ]
    }))
    def test_load_policies_success(self, mock_file):
        """Test that only enabled policies are loaded correctly."""
        fp = FileProcessor(self.mock_job_manager)
        self.assertEqual(len(fp._policies), 2)
        self.assertEqual(fp._policies[0]['id'], "P01")
        self.assertEqual(fp._policies[1]['id'], "P03")

    @patch("builtins.open")
    def test_load_policies_file_not_found(self, mock_open):
        """Test that an empty list is returned if policy.json is not found."""
        mock_open.side_effect = FileNotFoundError
        fp = FileProcessor(self.mock_job_manager)
        self.assertEqual(fp._policies, [])

    @patch("builtins.open", new_callable=mock_open, read_data="invalid json")
    def test_load_policies_malformed_json(self, mock_file):
        """Test that an empty list is returned if policy.json is malformed."""
        fp = FileProcessor(self.mock_job_manager)
        self.assertEqual(fp._policies, [])

    # ===== Test File Enumeration (_enumerate_files) =====

    @patch("os.walk")
    def test_enumerate_files_success(self, mock_walk):
        """Test that file enumeration correctly lists and sorts files."""
        mock_walk.return_value = [
            ('E:\\', ['dir1'], ['file2.txt']),
            ('E:\\dir1', [], ['file1.log'])
        ]
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        result = fp._enumerate_files(job, "E:\\")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], Path('E:\\dir1\\file1.log')) # Check for sorting
        self.assertEqual(result[1], Path('E:\\file2.txt'))
        self.mock_job_manager.log_event.assert_called_with(job, "ENUMERATION_COMPLETE", {"file_count": 2})

    @patch("os.walk", side_effect=OSError("Test OS Error"))
    def test_enumerate_files_os_error(self, mock_walk):
        """Test that enumeration returns None and fails the job on OSError."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        result = fp._enumerate_files(job, "E:\\")
        self.assertIsNone(result)
        self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED, ANY)

    # ===== Test Policy Enforcement (_enforce_policies & handlers) =====

    def test_policy_file_extension_blacklist_violation(self):
        """Test that the blacklist policy correctly identifies a forbidden file."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        file_list = [Path("safe.txt"), Path("danger.exe")]
        policy = {"id": "P01", "parameters": {"extensions": [".exe"]}}
        result = fp._policy_file_extension_blacklist(job, file_list, policy)
        self.assertFalse(result)
        self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED_POLICY, ANY)

    def test_policy_max_file_size_violation(self):
        """Test that the max file size policy correctly identifies a large file."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        file_list = [Path("large.dat")]
        policy = {"id": "P02", "parameters": {"max_size_mb": 1}}
        with patch("os.path.getsize", return_value=2 * 1024 * 1024): # 2MB file
            result = fp._policy_max_file_size(job, file_list, policy)
            self.assertFalse(result)
            self.mock_job_manager.update_state.assert_called_with(job, JobState.FAILED_POLICY, ANY)

    # ===== Test Threat Scanning (_scan_files) =====

    def test_scan_files_threat_found(self):
        """Test that the simulated scanner finds a threat."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        file_list = [Path("safe.txt"), Path("eicar.com")]
        result = fp._scan_files(job, file_list)
        self.assertFalse(result)
        self.mock_job_manager.update_state.assert_called_with(job, JobState.QUARANTINED, ANY)

    def test_scan_files_no_threat(self):
        """Test that the simulated scanner passes clean files."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        file_list = [Path("safe.txt"), Path("another.pdf")]
        result = fp._scan_files(job, file_list)
        self.assertTrue(result)

    # ===== Test Packaging (_package_job) =====

    @patch("gateway.file_processor.CryptoManager")
    def test_package_job_success(self, MockCryptoManager):
        """Test the happy path for packaging a job."""
        # Setup mocks
        mock_crypto_instance = MockCryptoManager.return_value
        mock_crypto_instance.generate_cek.return_value = b"key"
        mock_crypto_instance.encrypt_file.return_value = (b"ciphertext", b"nonce", b"tag")
        mock_crypto_instance.get_sha256_hash.return_value = "hash"

        fp = FileProcessor(self.mock_job_manager)
        job = Job()
        job.path = Path("test_job_path") # Mock job path
        file_list = [Path("E:\\file1.txt")]

        # Mock file system operations
        with patch("pathlib.Path.mkdir") as mock_mkdir:
            with patch("builtins.open", mock_open()) as mock_file:
                fp._package_job(job, file_list)

        # Assertions
        mock_mkdir.assert_called_once_with()
        mock_crypto_instance.save_cek_to_disk.assert_called_once()
        mock_crypto_instance.encrypt_file.assert_called_once()
        mock_file.assert_any_call(Path('test_job_path/data/hash'), 'wb') # Encrypted blob
        mock_file.assert_any_call(Path('test_job_path/manifest.json'), 'w') # Manifest
        self.mock_job_manager.log_event.assert_called_with(job, "PACKAGING_COMPLETE", ANY)

    # ===== Test Orchestration (process_device) =====

    def test_process_device_success_flow(self):
        """Test the main orchestration method for a successful run."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()

        # Mock the internal steps to test the orchestration logic
        with patch.object(fp, '_enumerate_files', return_value=[]) as mock_enum:
            with patch.object(fp, '_enforce_policies', return_value=True) as mock_policy:
                with patch.object(fp, '_scan_files', return_value=True) as mock_scan:
                    with patch.object(fp, '_package_job') as mock_package:
                        fp.process_device(job, "E:\\")

                        # Verify each step was called
                        mock_enum.assert_called_once()
                        mock_policy.assert_called_once()
                        mock_scan.assert_called_once()
                        mock_package.assert_called_once()

                        # Verify the final state is SUCCESS
                        self.mock_job_manager.update_state.assert_called_with(job, JobState.SUCCESS, ANY)

    def test_process_device_stops_on_policy_failure(self):
        """Test that orchestration stops if the policy check fails."""
        fp = FileProcessor(self.mock_job_manager)
        job = Job()

        with patch.object(fp, '_enumerate_files', return_value=[]) as mock_enum:
            with patch.object(fp, '_enforce_policies', return_value=False) as mock_policy:
                with patch.object(fp, '_scan_files') as mock_scan:
                    fp.process_device(job, "E:\\")

                    mock_enum.assert_called_once()
                    mock_policy.assert_called_once()
                    mock_scan.assert_not_called() # Should not proceed to scan

if __name__ == '__main__':
    unittest.main()