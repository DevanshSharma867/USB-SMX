"""
Integration tests for the Gateway Portal application.
These tests verify end-to-end workflows and component interactions.
"""

import unittest
from unittest.mock import patch, MagicMock, call
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
from gateway.job_manager import Job, JobState
from gateway.file_processor import FileProcessor, ScanVerdict
from gateway.crypto import CryptoManager


class TestGatewayIntegration(unittest.TestCase):
    """Integration tests for the complete Gateway Portal workflow."""

    def setUp(self):
        """Set up test environment with temporary directory."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_root = Path(self.temp_dir) / "test_drive"
        self.test_root.mkdir()
        
        # Create test files
        (self.test_root / "file1.txt").write_text("Test content 1")
        (self.test_root / "file2.log").write_text("Test content 2")
        (self.test_root / "subdir").mkdir()
        (self.test_root / "subdir" / "file3.txt").write_text("Test content 3")

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('gateway.device_manager.wmi.WMI')
    @patch('gateway.device_manager.pythoncom.CoInitialize')
    @patch('gateway.device_manager.pythoncom.CoUninitialize')
    def test_complete_usb_processing_workflow_clean_files(self, mock_co_uninit, mock_co_init, mock_wmi):
        """Test complete workflow from device insertion to job completion with clean files."""
        # Mock WMI responses
        mock_volume = MagicMock()
        mock_volume.DriveLetter = 'E:'
        mock_volume.DeviceID = 'volume_123'
        mock_volume.FileSystem = 'FAT32'
        
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "TEST123"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = 1000000000
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_instance = MagicMock()
        mock_wmi_instance.Win32_Volume.return_value = [mock_volume]
        mock_wmi.return_value = mock_wmi_instance
        
        # Create device manager
        device_manager = DeviceManager()
        
        # Mock file processor to return clean files
        with patch.object(device_manager._file_processor, 'enumerate_files') as mock_enumerate:
            mock_enumerate.return_value = [
                self.test_root / "file1.txt",
                self.test_root / "file2.log",
                self.test_root / "subdir" / "file3.txt"
            ]
            
            # Mock package_job to avoid actual file operations
            with patch.object(device_manager._file_processor, 'package_job') as mock_package:
                # Execute the workflow
                device_manager._handle_device_insertion('E:')
                
                # Verify the workflow was executed
                device_manager._job_manager.initialize_job.assert_called_once()
                mock_enumerate.assert_called_once()
                mock_package.assert_called_once()

    @patch('gateway.device_manager.wmi.WMI')
    @patch('gateway.device_manager.pythoncom.CoInitialize')
    @patch('gateway.device_manager.pythoncom.CoUninitialize')
    def test_complete_usb_processing_workflow_malware_detected(self, mock_co_uninit, mock_co_init, mock_wmi):
        """Test complete workflow when malware is detected."""
        # Mock WMI responses
        mock_volume = MagicMock()
        mock_volume.DriveLetter = 'E:'
        mock_volume.DeviceID = 'volume_123'
        mock_volume.FileSystem = 'FAT32'
        
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "TEST123"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = 1000000000
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_instance = MagicMock()
        mock_wmi_instance.Win32_Volume.return_value = [mock_volume]
        mock_wmi.return_value = mock_wmi_instance
        
        # Create device manager
        device_manager = DeviceManager()
        
        # Mock file processor to detect malware
        with patch.object(device_manager._file_processor, 'enumerate_files') as mock_enumerate:
            # Create a mock job that becomes quarantined
            mock_job = MagicMock()
            mock_job.state = JobState.QUARANTINED
            device_manager._job_manager.initialize_job.return_value = mock_job
            
            mock_enumerate.return_value = []  # No files returned due to quarantine
            
            # Mock package_job
            with patch.object(device_manager._file_processor, 'package_job') as mock_package:
                # Execute the workflow
                device_manager._handle_device_insertion('E:')
                
                # Verify the workflow was executed but package_job was not called
                device_manager._job_manager.initialize_job.assert_called_once()
                mock_enumerate.assert_called_once()
                mock_package.assert_not_called()

    def test_file_processor_integration_with_crypto(self):
        """Test FileProcessor integration with CryptoManager."""
        # Create a mock job manager
        mock_job_manager = MagicMock()
        
        # Create file processor
        with patch('gateway.file_processor.FileProcessor._find_mp_cmd_run', return_value=None):
            file_processor = FileProcessor(mock_job_manager)
        
        # Create a test job
        job = Job()
        job.state = JobState.INITIALIZED
        
        # Mock file enumeration to return test files
        with patch('gateway.file_processor.os.walk') as mock_walk:
            mock_walk.return_value = [
                (str(self.test_root), ['subdir'], ['file1.txt', 'file2.log']),
                (str(self.test_root / 'subdir'), [], ['file3.txt'])
            ]
            
            # Mock scan_file to return clean results
            with patch.object(file_processor, 'scan_file', return_value=(ScanVerdict.CLEAN, "Clean")):
                with patch.object(file_processor, '_get_alternate_data_streams', return_value=[]):
                    with patch.object(file_processor, '_is_path_safe', return_value=True):
                        # Test file enumeration
                        files = file_processor.enumerate_files(job, str(self.test_root))
                        
                        # Should return all files
                        self.assertEqual(len(files), 3)
                        
                        # Test job packaging
                        with patch('gateway.file_processor.CryptoManager') as mock_crypto:
                            mock_crypto_instance = mock_crypto.return_value
                            mock_crypto_instance.generate_cek.return_value = b'0' * 32
                            mock_crypto_instance.encrypt_file.return_value = (b'ciphertext', b'nonce', b'tag')
                            mock_crypto_instance.get_sha256_hash.return_value = 'file_hash'
                            mock_crypto_instance.create_manifest.return_value = {'manifest': 'data'}
                            mock_crypto_instance.sign_manifest_with_vault.return_value = {'signed': 'manifest'}
                            
                            with patch('builtins.open', mock_open()):
                                file_processor.package_job(job, files)
                                
                                # Verify crypto operations were called
                                self.assertEqual(mock_crypto_instance.encrypt_file.call_count, 3)
                                mock_crypto_instance.create_manifest.assert_called_once()
                                mock_crypto_instance.sign_manifest_with_vault.assert_called_once()

    def test_job_manager_integration_with_file_operations(self):
        """Test JobManager integration with file operations."""
        # Create job manager
        job_manager = JobManager()
        
        # Test job initialization with real file operations
        with patch('gateway.job_manager.JOB_ROOT_DIR', self.temp_dir / "jobs"):
            metadata = {
                "device_serial": "TEST123",
                "hostname": "TEST-HOST",
                "gateway_version": "0.1.0"
            }
            
            job = job_manager.initialize_job(metadata)
            
            self.assertIsNotNone(job)
            self.assertEqual(job.state, JobState.INITIALIZED)
            
            # Verify job directory was created
            self.assertTrue(job.path.exists())
            self.assertTrue((job.path / "metadata.json").exists())
            self.assertTrue((job.path / "state.json").exists())
            self.assertTrue((job.path / "logs.jsonl").exists())
            
            # Test state updates
            job_manager.update_state(job, JobState.ENUMERATING)
            self.assertEqual(job.state, JobState.ENUMERATING)
            
            job_manager.update_state(job, JobState.SCANNING)
            self.assertEqual(job.state, JobState.SCANNING)
            
            job_manager.update_state(job, JobState.SUCCESS)
            self.assertEqual(job.state, JobState.SUCCESS)

    def test_crypto_manager_integration_with_file_operations(self):
        """Test CryptoManager integration with real file operations."""
        crypto_manager = CryptoManager()
        
        # Test with real files
        test_file = self.test_root / "test_file.txt"
        test_file.write_text("This is a test file for encryption.")
        
        # Test encryption
        cek = crypto_manager.generate_cek()
        result = crypto_manager.encrypt_file(test_file, cek)
        
        self.assertIsNotNone(result)
        ciphertext, nonce, tag = result
        
        # Verify encryption produced different data
        self.assertNotEqual(ciphertext, test_file.read_bytes())
        
        # Test decryption
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(cek)
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        
        self.assertEqual(decrypted_data, test_file.read_bytes())

    def test_error_handling_integration(self):
        """Test error handling across components."""
        # Test device manager error handling
        device_manager = DeviceManager()
        
        # Mock WMI to raise exception
        with patch('gateway.device_manager.wmi.WMI', side_effect=Exception("WMI Error")):
            with patch('gateway.device_manager.pythoncom.CoInitialize'):
                with patch('gateway.device_manager.pythoncom.CoUninitialize'):
                    # Should not raise exception
                    device_manager._handle_device_insertion('E:')
        
        # Test file processor error handling
        mock_job_manager = MagicMock()
        with patch('gateway.file_processor.FileProcessor._find_mp_cmd_run', return_value=None):
            file_processor = FileProcessor(mock_job_manager)
        
        job = Job()
        job.state = JobState.INITIALIZED
        
        # Mock os.walk to raise exception
        with patch('gateway.file_processor.os.walk', side_effect=Exception("File system error")):
            result = file_processor.enumerate_files(job, "E:\\")
            
            # Should return empty list and update job state to FAILED
            self.assertEqual(len(result), 0)
            mock_job_manager.update_state.assert_called_with(job, JobState.FAILED)

    def test_concurrent_job_processing(self):
        """Test concurrent job processing."""
        device_manager = DeviceManager()
        
        # Mock multiple device insertions
        with patch('gateway.device_manager.wmi.WMI') as mock_wmi:
            mock_volume1 = MagicMock()
            mock_volume1.DriveLetter = 'E:'
            mock_volume1.DeviceID = 'volume_1'
            mock_volume1.FileSystem = 'FAT32'
            
            mock_volume2 = MagicMock()
            mock_volume2.DriveLetter = 'F:'
            mock_volume2.DeviceID = 'volume_2'
            mock_volume2.FileSystem = 'NTFS'
            
            # Mock metadata collection
            with patch.object(device_manager, '_collect_metadata') as mock_collect:
                mock_collect.return_value = {"device_serial": "TEST123"}
                
                # Mock job creation
                mock_job1 = MagicMock()
                mock_job1.state = JobState.INITIALIZED
                mock_job2 = MagicMock()
                mock_job2.state = JobState.INITIALIZED
                
                device_manager._job_manager.initialize_job.side_effect = [mock_job1, mock_job2]
                
                # Mock file processing
                with patch.object(device_manager._file_processor, 'enumerate_files', return_value=[]):
                    with patch.object(device_manager._file_processor, 'package_job'):
                        # Process both devices
                        device_manager._handle_device_insertion('E:')
                        device_manager._handle_device_insertion('F:')
                        
                        # Verify both jobs were created
                        self.assertEqual(device_manager._job_manager.initialize_job.call_count, 2)

    def test_memory_usage_with_large_files(self):
        """Test memory usage with large files."""
        # Create a large test file
        large_file = self.test_root / "large_file.txt"
        large_content = "X" * (10 * 1024 * 1024)  # 10MB
        large_file.write_text(large_content)
        
        crypto_manager = CryptoManager()
        
        # Test encryption of large file
        cek = crypto_manager.generate_cek()
        result = crypto_manager.encrypt_file(large_file, cek)
        
        self.assertIsNotNone(result)
        ciphertext, nonce, tag = result
        
        # Verify the encrypted data is different from original
        self.assertNotEqual(ciphertext, large_content.encode())

    def test_unicode_and_special_characters(self):
        """Test handling of unicode and special characters."""
        # Create files with unicode names and content
        unicode_file = self.test_root / "测试文件.txt"
        unicode_file.write_text("这是测试内容")
        
        special_char_file = self.test_root / "file with spaces & symbols!.txt"
        special_char_file.write_text("Special characters: !@#$%^&*()")
        
        crypto_manager = CryptoManager()
        
        # Test encryption of unicode files
        cek = crypto_manager.generate_cek()
        
        for file_path in [unicode_file, special_char_file]:
            result = crypto_manager.encrypt_file(file_path, cek)
            self.assertIsNotNone(result)
            
            # Test manifest creation with unicode paths
            file_metadata = {
                str(file_path): {
                    "sha256_encrypted": "test_hash",
                    "nonce": "test_nonce",
                    "tag": "test_tag"
                }
            }
            
            class MockJob:
                job_id = "test-job-unicode"
            
            manifest = crypto_manager.create_manifest(MockJob(), file_metadata)
            self.assertIn(str(file_path), manifest["files"])


if __name__ == '__main__':
    unittest.main()
