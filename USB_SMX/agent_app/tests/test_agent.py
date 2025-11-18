
import unittest
import sys
import tempfile
import shutil
import json
import queue
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from agent_portal.agent_file_processor import AgentFileProcessor
from gateway.crypto import CryptoManager
from agent_portal.agent_gui import GuiManager
from agent_portal.agent_device_manager import AgentDeviceManager

class TestAgentIntegration(unittest.TestCase):

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.gateway_crypto = CryptoManager()
        self.agent_processor = AgentFileProcessor()

        # Create a dummy file to be encrypted
        self.original_file_content = b"This is a secret message for the agent."
        self.original_file_path = self.temp_dir / "original_file.txt"
        with open(self.original_file_path, "wb") as f:
            f.write(self.original_file_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_end_to_end_decryption_with_status_updates(self):
        # 1. Gateway side: Encrypt a file and create a manifest
        cek = self.gateway_crypto.generate_cek()
        encrypted_data, nonce, tag = self.gateway_crypto.encrypt_file(self.original_file_path, cek)
        
        encrypted_blob_name = self.gateway_crypto.get_sha256_hash(self.original_file_path.name.encode())
        
        job_dir = self.temp_dir / "job"
        data_dir = job_dir / "data"
        data_dir.mkdir(parents=True)

        with open(data_dir / encrypted_blob_name, "wb") as f:
            f.write(encrypted_data)

        manifest = {
            "job_id": "test-decryption-job",
            "files": {
                str(self.original_file_path): {
                    "encrypted_blob_name": encrypted_blob_name,
                    "sha256_encrypted": self.gateway_crypto.get_sha256_hash(encrypted_data),
                    "nonce": nonce.hex(),
                    "tag": tag.hex()
                }
            }
        }
        signed_manifest = self.gateway_crypto.sign_manifest(manifest)

        with open(job_dir / "manifest.json", "w") as f:
            json.dump(signed_manifest, f)

        self.gateway_crypto.save_cek_to_disk(cek, job_dir / "cek.key")

        # 2. Agent side: Process the encrypted job and check for status updates
        msg_queue = queue.Queue()
        output_dir = self.temp_dir / "decrypted"
        self.agent_processor.process_encrypted_job(job_dir, output_dir, msg_queue, str(job_dir))

        # 3. Verification
        decrypted_file_path = output_dir / self.original_file_path.name
        self.assertTrue(decrypted_file_path.exists())
        
        with open(decrypted_file_path, "rb") as f:
            decrypted_content = f.read()
        
        self.assertEqual(decrypted_content, self.original_file_content)

        # Check for status updates in the queue
        expected_statuses = ["VERIFYING_SIGNATURE", "DECRYPTING", "COMPLETE"]
        actual_statuses = []
        while not msg_queue.empty():
            msg = msg_queue.get_nowait()
            if msg["event"] == "STATUS_UPDATE":
                actual_statuses.append(msg["status"])
        
        self.assertEqual(actual_statuses, expected_statuses)

    @patch('agent_portal.agent_device_manager.wmi')
    @patch('agent_portal.agent_device_manager.time')
    def test_device_removal(self, mock_time, mock_wmi):
        # 1. Setup
        msg_queue = queue.Queue()
        device_manager = AgentDeviceManager(msg_queue)
        device_manager._stop_event.set() # Ensure the loop runs only once

        # 2. Simulate that a device was present and is now removed
        device_manager.active_jobs_by_drive['E:'] = 'test_job_path'
        mock_wmi.WMI.return_value.Win32_LogicalDisk.return_value = [] # No drives are currently connected

        # 3. Run the monitor
        with patch('pathlib.Path.exists', return_value=False):
            device_manager._monitor_devices()

        # 4. Verification
        self.assertFalse(msg_queue.empty())
        msg = msg_queue.get_nowait()
        self.assertEqual(msg["event"], "DEVICE_REMOVED")
        self.assertEqual(msg["job_path"], "test_job_path")

if __name__ == '__main__':
    unittest.main()
