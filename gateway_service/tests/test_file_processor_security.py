import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.file_processor import FileProcessor
from gateway.job_manager import Job, JobState

class TestFileProcessorSecurity(unittest.TestCase):
    """Security-focused tests for the FileProcessor."""

    def setUp(self):
        """Set up a mock JobManager for each test."""
        self.mock_job_manager = MagicMock()
        self.file_processor = FileProcessor(self.mock_job_manager)
        self.job = Job()

    def test_is_path_safe(self):
        """Test the _is_path_safe method with various inputs."""
        root = Path('/root')

        # Safe paths
        self.assertTrue(self.file_processor._is_path_safe(Path('/root/safe/path'), root))
        self.assertTrue(self.file_processor._is_path_safe(Path('/root/file.txt'), root))

        # Unsafe paths (directory traversal)
        self.assertFalse(self.file_processor._is_path_safe(Path('/root/../unsafe/path'), root))
        self.assertFalse(self.file_processor._is_path_safe(Path('/root/../../etc/passwd'), root))
        self.assertFalse(self.file_processor._is_path_safe(Path('../etc/passwd'), root))

        # Unsafe paths (absolute paths outside the root)
        self.assertFalse(self.file_processor._is_path_safe(Path('/etc/passwd'), root))

        # Unsafe paths (null bytes)
        self.assertFalse(self.file_processor._is_path_safe(Path('/root/safe/path\x00'), root))

        # Unsafe paths (long paths)
        long_path = '/root/' + 'a' * 300
        self.assertFalse(self.file_processor._is_path_safe(Path(long_path), root))

    def test_policy_file_extension_blacklist(self):
        """Test the _policy_file_extension_blacklist method."""
        policy = {
            "id": "POLICY-001",
            "parameters": {
                "extensions": [".exe", ".dll"]
            }
        }
        file_list = [Path("safe.txt"), Path("unsafe.exe")]

        result = self.file_processor._policy_file_extension_blacklist(self.job, file_list, policy)

        self.assertFalse(result)
        self.mock_job_manager.update_state.assert_called_once_with(
            self.job,
            JobState.FAILED_POLICY,
            {
                "policy_id": "POLICY-001",
                "file_path": str(Path("unsafe.exe")),
                "reason": "File extension '.exe' is blacklisted."
            }
        )

    @patch('gateway.file_processor.os.path.getsize')
    def test_policy_max_file_size(self, mock_getsize):
        """Test the _policy_max_file_size method."""
        policy = {
            "id": "POLICY-002",
            "parameters": {
                "max_size_mb": 1
            }
        }
        file_list = [Path("small.txt"), Path("large.dat")]
        mock_getsize.side_effect = [500, 2 * 1024 * 1024]  # 500 bytes and 2 MB

        result = self.file_processor._policy_max_file_size(self.job, file_list, policy)

        self.assertFalse(result)
        self.mock_job_manager.update_state.assert_called_once_with(
            self.job,
            JobState.FAILED_POLICY,
            {
                "policy_id": "POLICY-002",
                "file_path": str(Path("large.dat")),
                "file_size_mb": 2.0,
                "reason": "File size (2.0 MB) exceeds the limit of 1 MB."
            }
        )

if __name__ == '__main__':
    unittest.main()