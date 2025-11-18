
import unittest
from unittest.mock import patch, MagicMock, call
import sys
import threading
import time
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

# Mock wmi and pythoncom before they are imported by device_manager
# This prevents the test environment from needing these Windows-specific libraries
mock_wmi = MagicMock()
sys.modules['wmi'] = mock_wmi
sys.modules['pythoncom'] = MagicMock()

from gateway.device_manager import DeviceManager

# A mock WMI Volume object
def create_mock_volume(drive_letter, device_id):
    vol = MagicMock()
    vol.DriveLetter = drive_letter
    vol.DeviceID = device_id
    return vol

class TestDeviceManager(unittest.TestCase):

    def setUp(self):
        """Patch all external dependencies of DeviceManager."""
        # Patch the dependencies that are instantiated within DeviceManager
        self.job_manager_patch = patch('gateway.device_manager.JobManager', MagicMock())
        self.file_processor_patch = patch('gateway.device_manager.FileProcessor', MagicMock())
        
        self.mock_job_manager = self.job_manager_patch.start()
        self.mock_file_processor = self.file_processor_patch.start()

        self.device_manager = DeviceManager()

    def tearDown(self):
        """Stop all patches."""
        self.job_manager_patch.stop()
        self.file_processor_patch.stop()

    @patch('gateway.device_manager.threading.Thread')
    def test_start_monitoring_creates_thread(self, mock_thread):
        """Test that start_monitoring starts a new thread."""
        self.device_manager.start_monitoring()
        mock_thread.assert_called_once_with(target=self.device_manager._monitor_devices, daemon=True)
        self.device_manager._monitoring_thread.start.assert_called_once()

    @patch('gateway.device_manager.time.sleep') # Mock sleep to avoid waiting
    @patch('gateway.device_manager.DeviceManager._handle_device_removal')
    @patch('gateway.device_manager.DeviceManager._handle_device_insertion')
    def test_monitor_devices_insertion_and_removal(self, mock_handle_insertion, mock_handle_removal, mock_sleep):
        """Test the device monitoring loop for insertion and removal."""
        # --- Test Setup ---
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [], # 0. Initial call for known_volumes
            [create_mock_volume('E:', 'device1')], # 1. Insertion detected
            [], # 2. Removal detected
            [], # 3. Final state in loop
        ]

        # This mock allows us to control the loop
        stop_event = MagicMock()
        stop_event.is_set.side_effect = [False, False, False, False, True] # Run loop 4 times
        self.device_manager._stop_event = stop_event

        # --- Run Test ---
        self.device_manager._monitor_devices()

        # --- Assertions ---
        # Check that insertion was handled
        mock_handle_insertion.assert_called_once_with('E:')
        # Check that removal was handled
        mock_handle_removal.assert_called_once_with('E:')

    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    def test_handle_device_insertion_success(self, mock_collect_metadata):
        """Test the successful processing of a device insertion."""
        # --- Test Setup ---
        drive_letter = 'E:'
        mock_collect_metadata.return_value = {'serial': '123'}
        mock_wmi.WMI.return_value.Win32_Volume.return_value = [create_mock_volume(drive_letter, 'id1')]
        
        # Mock the return of the job manager
        mock_job = MagicMock()
        self.mock_job_manager.return_value.initialize_job.return_value = mock_job

        # --- Run Test ---
        self.device_manager._handle_device_insertion(drive_letter)

        # --- Assertions ---
        # Verify that the full workflow was called
        mock_collect_metadata.assert_called_once()
        self.mock_job_manager.return_value.initialize_job.assert_called_once_with({'serial': '123'})
        self.mock_file_processor.return_value.enumerate_files.assert_called_once_with(mock_job, 'E:\\')
        self.mock_file_processor.return_value.package_job.assert_called_once()

    @patch('gateway.device_manager.DeviceManager._collect_metadata')
    def test_handle_device_insertion_metadata_fails(self, mock_collect_metadata):
        """Test that processing aborts if metadata collection fails."""
        mock_collect_metadata.return_value = None
        mock_wmi.WMI.return_value.Win32_Volume.return_value = [create_mock_volume('E:', 'id1')]

        self.device_manager._handle_device_insertion('E:')

        # Verify that the workflow was aborted
        self.mock_job_manager.return_value.initialize_job.assert_not_called()
        self.mock_file_processor.return_value.enumerate_files.assert_not_called()

    def test_handle_device_insertion_wmi_volume_not_found(self):
        """Test device insertion when WMI volume object is not found."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = IndexError("Volume not found")
        
        self.device_manager._handle_device_insertion('E:')
        
        # Should not proceed with job creation
        self.mock_job_manager.return_value.initialize_job.assert_not_called()

    def test_handle_device_insertion_job_creation_fails(self):
        """Test device insertion when job creation fails."""
        mock_wmi.WMI.return_value.Win32_Volume.return_value = [create_mock_volume('E:', 'id1')]
        self.mock_job_manager.return_value.initialize_job.return_value = None
        
        with patch('gateway.device_manager.DeviceManager._collect_metadata', return_value={'serial': '123'}):
            self.device_manager._handle_device_insertion('E:')
        
        # Should not proceed with file processing
        self.mock_file_processor.return_value.enumerate_files.assert_not_called()

    def test_handle_device_insertion_file_enumeration_fails(self):
        """Test device insertion when file enumeration fails."""
        mock_wmi.WMI.return_value.Win32_Volume.return_value = [create_mock_volume('E:', 'id1')]
        mock_job = MagicMock()
        self.mock_job_manager.return_value.initialize_job.return_value = mock_job
        self.mock_file_processor.return_value.enumerate_files.return_value = []
        
        with patch('gateway.device_manager.DeviceManager._collect_metadata', return_value={'serial': '123'}):
            self.device_manager._handle_device_insertion('E:')
        
        # Should still call package_job with empty file list
        self.mock_file_processor.return_value.package_job.assert_called_once()

    def test_handle_device_insertion_quarantined_job(self):
        """Test device insertion when job becomes quarantined."""
        mock_wmi.WMI.return_value.Win32_Volume.return_value = [create_mock_volume('E:', 'id1')]
        mock_job = MagicMock()
        mock_job.state = JobState.QUARANTINED
        self.mock_job_manager.return_value.initialize_job.return_value = mock_job
        self.mock_file_processor.return_value.enumerate_files.return_value = []
        
        with patch('gateway.device_manager.DeviceManager._collect_metadata', return_value={'serial': '123'}):
            self.device_manager._handle_device_insertion('E:')
        
        # Should not call package_job for quarantined jobs
        self.mock_file_processor.return_value.package_job.assert_not_called()

    def test_handle_device_removal(self):
        """Test device removal handling."""
        # This is currently a placeholder method, but test it exists
        self.device_manager._handle_device_removal('E:')
        # Should not raise any exceptions

    def test_collect_metadata_success_method1(self):
        """Test metadata collection using method 1 (Volume->Partition->DiskDrive)."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "ABC123"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = 1000000000
        mock_volume.FileSystem = "FAT32"
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        
        result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['device_serial'], 'ABC123')
        self.assertEqual(result['volume_guid'], 'volume_id')
        self.assertEqual(result['filesystem_type'], 'FAT32')

    def test_collect_metadata_success_method2(self):
        """Test metadata collection using method 2 (LogicalDisk->Partition->DiskDrive)."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_volume.associators.return_value = []  # Method 1 fails
        
        mock_logical_disk = MagicMock()
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "DEF456"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = 2000000000
        mock_volume.FileSystem = "NTFS"
        
        mock_logical_disk.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        mock_wmi_connection.Win32_LogicalDisk.return_value = [mock_logical_disk]
        
        result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['device_serial'], 'DEF456')

    def test_collect_metadata_no_drive_letter(self):
        """Test metadata collection when volume has no drive letter."""
        mock_volume = MagicMock()
        mock_volume.DriveLetter = None
        
        result = self.device_manager._collect_metadata(MagicMock(), mock_volume)
        
        self.assertIsNone(result)

    def test_collect_metadata_no_disk_drive_found(self):
        """Test metadata collection when no disk drive is found."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_volume.associators.return_value = []  # Method 1 fails
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        mock_wmi_connection.Win32_LogicalDisk.return_value = []  # Method 2 fails
        
        result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        self.assertIsNone(result)

    def test_collect_metadata_index_error(self):
        """Test metadata collection when IndexError occurs."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_volume.associators.side_effect = IndexError("No partitions found")
        
        result = self.device_manager._collect_metadata(MagicMock(), mock_volume)
        
        self.assertIsNone(result)

    def test_collect_metadata_general_exception(self):
        """Test metadata collection when general exception occurs."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_volume.associators.side_effect = Exception("WMI error")
        
        result = self.device_manager._collect_metadata(MagicMock(), mock_volume)
        
        self.assertIsNone(result)

    def test_collect_metadata_missing_serial_number(self):
        """Test metadata collection when serial number is missing."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = None
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = 1000000000
        mock_volume.FileSystem = "FAT32"
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        
        result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['device_serial'], 'N/A')

    def test_collect_metadata_missing_size(self):
        """Test metadata collection when size is missing."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "ABC123"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678"
        mock_disk_drive.Size = None
        mock_volume.FileSystem = "FAT32"
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        
        result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        self.assertIsNotNone(result)
        self.assertEqual(result['device_capacity'], 0)

    @patch('gateway.device_manager.time.sleep')
    def test_monitor_devices_exception_handling(self, mock_sleep):
        """Test that exceptions in monitoring loop are handled gracefully."""
        mock_wmi.WMI.side_effect = Exception("WMI connection failed")
        
        stop_event = MagicMock()
        stop_event.is_set.side_effect = [False, True]  # Run once then stop
        self.device_manager._stop_event = stop_event
        
        # Should not raise exception
        self.device_manager._monitor_devices()
        
        # Should have slept after the exception
        mock_sleep.assert_called_with(5)

    def test_start_monitoring_already_running(self):
        """Test starting monitoring when already running."""
        # Start monitoring first time
        self.device_manager.start_monitoring()
        first_thread = self.device_manager._monitoring_thread
        
        # Try to start again
        self.device_manager.start_monitoring()
        
        # Should be the same thread
        self.assertEqual(self.device_manager._monitoring_thread, first_thread)

    def test_stop_monitoring_not_running(self):
        """Test stopping monitoring when not running."""
        # Should not raise exception
        self.device_manager.stop_monitoring()

    def test_stop_monitoring_timeout(self):
        """Test stopping monitoring with thread join timeout."""
        # Start monitoring
        self.device_manager.start_monitoring()
        
        # Mock thread to not join within timeout
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        mock_thread.join.return_value = None  # Timeout
        self.device_manager._monitoring_thread = mock_thread
        
        # Should not raise exception
        self.device_manager.stop_monitoring()
        
        mock_thread.join.assert_called_once_with(timeout=5)

    def test_monitor_devices_multiple_insertions(self):
        """Test monitoring with multiple device insertions."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [],  # Initial state
            [create_mock_volume('E:', 'device1'), create_mock_volume('F:', 'device2')],  # Two insertions
            [],  # Final state
        ]
        
        stop_event = MagicMock()
        stop_event.is_set.side_effect = [False, False, True]  # Run twice then stop
        self.device_manager._stop_event = stop_event
        
        with patch('gateway.device_manager.DeviceManager._handle_device_insertion') as mock_handle:
            self.device_manager._monitor_devices()
            
            # Should handle both insertions
            self.assertEqual(mock_handle.call_count, 2)
            mock_handle.assert_any_call('E:')
            mock_handle.assert_any_call('F:')

    def test_monitor_devices_multiple_removals(self):
        """Test monitoring with multiple device removals."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [create_mock_volume('E:', 'device1'), create_mock_volume('F:', 'device2')],  # Initial state
            [],  # Both removed
            [],  # Final state
        ]
        
        stop_event = MagicMock()
        stop_event.is_set.side_effect = [False, False, True]  # Run twice then stop
        self.device_manager._stop_event = stop_event
        
        with patch('gateway.device_manager.DeviceManager._handle_device_removal') as mock_handle:
            self.device_manager._monitor_devices()
            
            # Should handle both removals
            self.assertEqual(mock_handle.call_count, 2)
            mock_handle.assert_any_call('E:')
            mock_handle.assert_any_call('F:')

    def test_monitor_devices_mixed_insertions_removals(self):
        """Test monitoring with mixed insertions and removals."""
        mock_wmi.WMI.return_value.Win32_Volume.side_effect = [
            [create_mock_volume('E:', 'device1')],  # Initial state
            [create_mock_volume('F:', 'device2')],  # E: removed, F: inserted
            [],  # F: removed
        ]
        
        stop_event = MagicMock()
        stop_event.is_set.side_effect = [False, False, False, True]  # Run three times then stop
        self.device_manager._stop_event = stop_event
        
        with patch('gateway.device_manager.DeviceManager._handle_device_insertion') as mock_handle_insertion:
            with patch('gateway.device_manager.DeviceManager._handle_device_removal') as mock_handle_removal:
                self.device_manager._monitor_devices()
                
                # Should handle one insertion and two removals
                mock_handle_insertion.assert_called_once_with('F:')
                self.assertEqual(mock_handle_removal.call_count, 2)
                mock_handle_removal.assert_any_call('E:')
                mock_handle_removal.assert_any_call('F:')

    def test_device_manager_initialization(self):
        """Test DeviceManager initialization."""
        manager = DeviceManager()
        
        self.assertIsNotNone(manager._job_manager)
        self.assertIsNotNone(manager._file_processor)
        self.assertIsNone(manager._monitoring_thread)
        self.assertIsNotNone(manager._stop_event)

    def test_collect_metadata_complete_metadata(self):
        """Test metadata collection with complete metadata."""
        mock_volume = create_mock_volume('E:', 'volume_id')
        mock_partition = MagicMock()
        mock_disk_drive = MagicMock()
        mock_disk_drive.SerialNumber = "ABC123"
        mock_disk_drive.PNPDeviceID = "USB\\VID_1234&PID_5678\\5&12345678&0&1"
        mock_disk_drive.Size = 1000000000
        mock_volume.FileSystem = "FAT32"
        
        mock_volume.associators.return_value = [mock_partition]
        mock_partition.associators.return_value = [mock_disk_drive]
        
        mock_wmi_connection = MagicMock()
        mock_wmi_connection.Win32_Volume.return_value = [mock_volume]
        
        with patch('gateway.device_manager.datetime') as mock_datetime:
            mock_datetime.datetime.utcnow.return_value.isoformat.return_value = "2023-01-01T12:00:00"
            with patch('gateway.device_manager.socket.gethostname', return_value="TEST-HOST"):
                result = self.device_manager._collect_metadata(mock_wmi_connection, mock_volume)
        
        expected_keys = [
            'device_serial', 'volume_guid', 'product_id', 'device_capacity',
            'filesystem_type', 'insertion_timestamp', 'hostname', 'gateway_version'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        self.assertEqual(result['device_serial'], 'ABC123')
        self.assertEqual(result['volume_guid'], 'volume_id')
        self.assertEqual(result['product_id'], 'USB\\VID_1234&PID_5678\\5&12345678&0&1')
        self.assertEqual(result['device_capacity'], 1000000000)
        self.assertEqual(result['filesystem_type'], 'FAT32')
        self.assertEqual(result['hostname'], 'TEST-HOST')
        self.assertEqual(result['gateway_version'], '0.1.0')

if __name__ == '__main__':
    unittest.main()
