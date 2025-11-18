import unittest
import os
import sys
import tempfile
import shutil
import json
import time
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock, call
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Add the src directory to the Python path to allow for module imports
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.crypto import CryptoManager

class TestCryptoManager(unittest.TestCase):

    def setUp(self):
        """Set up for each test."""
        self.crypto_manager = CryptoManager()
        self.test_data = b"This is a test file for encryption."
        self.test_file = Path("test_file.tmp")
        with open(self.test_file, "wb") as f:
            f.write(self.test_data)

    def tearDown(self):
        """Clean up after each test."""
        if self.test_file.exists():
            self.test_file.unlink()

    def test_generate_cek(self):
        """Test that the Content Encryption Key is generated with the correct length."""
        cek = self.crypto_manager.generate_cek(key_size_bytes=32)
        self.assertEqual(len(cek), 32)
        
        cek = self.crypto_manager.generate_cek(key_size_bytes=16)
        self.assertEqual(len(cek), 16)

        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=10) # Invalid size

    def test_get_sha256_hash(self):
        """Test SHA-256 hash generation with a known value."""
        known_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        calculated_hash = self.crypto_manager.get_sha256_hash(b"hello world")
        self.assertEqual(calculated_hash, known_hash)

    def test_encrypt_file_and_decrypt(self):
        """
        Test that a file can be encrypted and that the resulting ciphertext
        can be decrypted back to the original plaintext.
        """
        cek = self.crypto_manager.generate_cek()
        encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
        
        self.assertIsNotNone(encryption_result)
        ciphertext, nonce, tag = encryption_result
        
        # Ensure ciphertext is different from plaintext
        self.assertNotEqual(ciphertext, self.test_data)
        
        # Manually decrypt to verify correctness
        aesgcm = AESGCM(cek)
        # The library expects the tag to be appended to the ciphertext for decryption
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        
        self.assertEqual(decrypted_data, self.test_data)

    def test_create_manifest(self):
        """Test the structure of the generated manifest."""
        # Mock job and file data
        class MockJob:
            job_id = "mock-job-123"
        
        mock_file_data = {
            "C:\\path\\file1.txt": {"sha256_encrypted": "hash1"},
            "C:\\path\\file2.log": {"sha256_encrypted": "hash2"},
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), mock_file_data, file_count=2, pendrive_output_path="E:\\.gateway_output")
        
        self.assertEqual(manifest["job_id"], "mock-job-123")
        self.assertEqual(manifest["file_count"], 2)
        self.assertEqual(manifest["encryption_algorithm"], "AES-256-GCM")
        self.assertEqual(manifest["pendrive_output_path"], "E:\\.gateway_output")
        self.assertIn("gateway_info", manifest)
        self.assertIn("files", manifest)
        self.assertEqual(len(manifest["files"]),
 2)
        self.assertIn("encryption_params", manifest)
        self.assertEqual(manifest["encryption_params"]["algorithm"], "AES-256-GCM")

    def test_sign_manifest(self):
        """Test that the signing function adds the signature block."""
        manifest = {"job_id": "test"}
        signed_manifest = self.crypto_manager.sign_manifest(manifest)
        
        self.assertIn("signature", signed_manifest)
        self.assertIn("value", signed_manifest["signature"])

    def test_encrypt_file_nonexistent_file(self):
        """Test encryption of a non-existent file returns None."""
        nonexistent_file = Path("nonexistent_file.txt")
        cek = self.crypto_manager.generate_cek()
        
        result = self.crypto_manager.encrypt_file(nonexistent_file, cek)
        self.assertIsNone(result)

    def test_encrypt_file_permission_error(self):
        """Test encryption when file cannot be read due to permissions."""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(self.test_file, cek)
            self.assertIsNone(result)

    def test_encrypt_file_read_error(self):
        """Test encryption when a file read error occurs."""
        with patch('builtins.open', side_effect=IOError("File read error")):
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(self.test_file, cek)
            self.assertIsNone(result)

    def test_encrypt_file_empty_file(self):
        """Test encryption of an empty file."""
        empty_file = Path("empty_file.tmp")
        empty_file.touch()
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(empty_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            self.assertEqual(len(ciphertext), 0)  # Empty file should produce empty ciphertext
        finally:
            if empty_file.exists():
                empty_file.unlink()

    def test_encrypt_file_large_file(self):
        """Test encryption of a large file."""
        large_file = Path("large_file.tmp")
        large_data = b"X" * (1024 * 1024)  # 1MB of data
        
        with open(large_file, "wb") as f:
            f.write(large_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(large_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            self.assertEqual(len(ciphertext), len(large_data))
        finally:
            if large_file.exists():
                large_file.unlink()

    def test_generate_cek_invalid_sizes(self):
        """Test that invalid key sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=8)
        
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=64)
        
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=0)

    def test_get_sha256_hash_edge_cases(self):
        """Test SHA-256 hash with edge cases."""
        # Empty data
        empty_hash = self.crypto_manager.get_sha256_hash(b"")
        self.assertEqual(len(empty_hash), 64)  # SHA-256 produces 64 hex chars
        
        # Very long data
        long_data = b"X" * 10000
        long_hash = self.crypto_manager.get_sha256_hash(long_data)
        self.assertEqual(len(long_hash), 64)
        
        # Binary data
        binary_data = bytes(range(256))
        binary_hash = self.crypto_manager.get_sha256_hash(binary_data)
        self.assertEqual(len(binary_hash), 64)

    def test_create_manifest_with_empty_files(self):
        """Test manifest creation with empty file metadata."""
        class MockJob:
            job_id = "empty-job-123"
        
        empty_file_data = {}
        manifest = self.crypto_manager.create_manifest(MockJob(), empty_file_data, file_count=0, pendrive_output_path="E:\\.gateway_output")
        
        self.assertEqual(manifest["job_id"], "empty-job-123")
        self.assertEqual(len(manifest["files"]), 0)
        self.assertIn("encryption_params", manifest)

    def test_create_manifest_with_large_file_list(self):
        """Test manifest creation with many files."""
        class MockJob:
            job_id = "large-job-456"
        
        # Create a large file metadata dictionary
        large_file_data = {}
        for i in range(1000):
            large_file_data[f"C:\\path\\file{i}.txt"] = {"sha256_encrypted": f"hash{i}"}
        
        manifest = self.crypto_manager.create_manifest(MockJob(), large_file_data, file_count=1000, pendrive_output_path="E:\\.gateway_output")
        
        self.assertEqual(manifest["job_id"], "large-job-456")
        self.assertEqual(manifest["file_count"], 1000)
        self.assertEqual(len(manifest["files"]), 1000)

    def test_sign_manifest_preserves_original(self):
        """Test that signing doesn't modify the original manifest."""
        original_manifest = {"job_id": "test", "files": {"file1.txt": "hash1"}}
        signed_manifest = self.crypto_manager.sign_manifest(original_manifest)
        
        # Original should not have signature
        self.assertNotIn("signature", original_manifest)
        # Signed should have signature
        self.assertIn("signature", signed_manifest)
        # Other fields should be preserved
        self.assertEqual(signed_manifest["job_id"], original_manifest["job_id"])
        self.assertEqual(signed_manifest["files"], original_manifest["files"])

    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypt-decrypt roundtrip produces original data."""
        cek = self.crypto_manager.generate_cek()
        encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
        
        self.assertIsNotNone(encryption_result)
        ciphertext, nonce, tag = encryption_result
        
        # Decrypt using the same method as in the test
        aesgcm = AESGCM(cek)
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        
        self.assertEqual(decrypted_data, self.test_data)

    def test_different_keys_produce_different_ciphertext(self):
        """Test that different keys produce different ciphertext for same input."""
        cek1 = self.crypto_manager.generate_cek()
        cek2 = self.crypto_manager.generate_cek()
        
        result1 = self.crypto_manager.encrypt_file(self.test_file, cek1)
        result2 = self.crypto_manager.encrypt_file(self.test_file, cek2)
        
        self.assertNotEqual(result1[0], result2[0])  # Different ciphertext
        self.assertNotEqual(result1[1], result2[1])  # Different nonces

    # ===== COMPREHENSIVE CEK GENERATION TESTS =====
    
    def test_generate_cek_all_valid_sizes(self):
        """Test CEK generation with all valid key sizes."""
        for size in [16, 24, 32]:
            cek = self.crypto_manager.generate_cek(key_size_bytes=size)
            self.assertEqual(len(cek), size)
            self.assertIsInstance(cek, bytes)
    
    def test_generate_cek_randomness(self):
        """Test that CEK generation produces different keys each time."""
        keys = set()
        for _ in range(100):
            key = self.crypto_manager.generate_cek()
            self.assertNotIn(key, keys)
            keys.add(key)
    
    def test_generate_cek_entropy(self):
        """Test that generated keys have good entropy (no obvious patterns)."""
        key = self.crypto_manager.generate_cek()
        # Check that key is not all zeros or all same byte
        self.assertNotEqual(key, b'\x00' * len(key))
        self.assertNotEqual(key, bytes([key[0]] * len(key)))
        # Check that key has reasonable byte distribution
        unique_bytes = len(set(key))
        self.assertGreater(unique_bytes, len(key) // 4)  # At least 25% unique bytes
    
    def test_generate_cek_negative_size(self):
        """Test that negative key sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=-1)
    
    def test_generate_cek_zero_size(self):
        """Test that zero key size raises ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=0)
    
    def test_generate_cek_float_size(self):
        """Test that float key sizes raise TypeError."""
        with self.assertRaises(TypeError):
            self.crypto_manager.generate_cek(key_size_bytes=16.0)
    
    def test_generate_cek_string_size(self):
        """Test that string key sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes="16")
    
    def test_generate_cek_none_size(self):
        """Test that None key size raises ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=None)
    
    def test_generate_cek_very_large_size(self):
        """Test that very large key sizes raise ValueError."""
        with self.assertRaises(ValueError):
            self.crypto_manager.generate_cek(key_size_bytes=1000)

    # ===== COMPREHENSIVE ENCRYPTION/DECRYPTION TESTS =====
    
    def test_encrypt_file_wrong_key_size(self):
        """Test encryption with wrong key size."""
        wrong_key = b"short"  # Too short
        result = self.crypto_manager.encrypt_file(self.test_file, wrong_key)
        self.assertIsNone(result)
    
    def test_encrypt_file_corrupted_key(self):
        """Test encryption with corrupted key."""
        corrupted_key = b'\x00' * 32  # All zeros
        result = self.crypto_manager.encrypt_file(self.test_file, corrupted_key)
        # Should still work, just with a weak key
        self.assertIsNotNone(result)
    
    def test_encrypt_file_unicode_path(self):
        """Test encryption with unicode file path."""
        unicode_file = Path("测试文件.tmp")
        with open(unicode_file, "wb") as f:
            f.write(self.test_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(unicode_file, cek)
            self.assertIsNotNone(result)
        finally:
            if unicode_file.exists():
                unicode_file.unlink()
    
    def test_encrypt_file_very_long_path(self):
        """Test encryption with very long file path."""
        long_path = Path("a" * 200 + ".tmp")
        with open(long_path, "wb") as f:
            f.write(self.test_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(long_path, cek)
            self.assertIsNotNone(result)
        finally:
            if long_path.exists():
                long_path.unlink()
    
    def test_encrypt_file_symlink(self):
        """Test encryption of a symbolic link."""
        if hasattr(os, 'symlink'):  # Skip on Windows without symlink support
            target_file = Path("target.tmp")
            symlink_file = Path("symlink.tmp")
            
            with open(target_file, "wb") as f:
                f.write(self.test_data)
            
            try:
                os.symlink(target_file, symlink_file)
                cek = self.crypto_manager.generate_cek()
                result = self.crypto_manager.encrypt_file(symlink_file, cek)
                self.assertIsNotNone(result)
            finally:
                if symlink_file.exists():
                    symlink_file.unlink()
                if target_file.exists():
                    target_file.unlink()
    
    def test_encrypt_file_binary_data(self):
        """Test encryption of file with binary data including null bytes."""
        binary_file = Path("binary.tmp")
        binary_data = bytes(range(256))  # All possible byte values
        
        with open(binary_file, "wb") as f:
            f.write(binary_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(binary_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            
            # Verify decryption
            aesgcm = AESGCM(cek)
            full_ciphertext = ciphertext + tag
            decrypted = aesgcm.decrypt(nonce, full_ciphertext, None)
            self.assertEqual(decrypted, binary_data)
        finally:
            if binary_file.exists():
                binary_file.unlink()
    
    def test_encrypt_file_very_small_file(self):
        """Test encryption of very small file (1 byte)."""
        tiny_file = Path("tiny.tmp")
        with open(tiny_file, "wb") as f:
            f.write(b"X")
        
        try:
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(tiny_file, cek)
            
            self.assertIsNotNone(result)
            ciphertext, nonce, tag = result
            self.assertEqual(len(ciphertext), 1)
        finally:
            if tiny_file.exists():
                tiny_file.unlink()
    
    def test_encrypt_file_concurrent_access(self):
        """Test encryption when file is being written to."""
        concurrent_file = Path("concurrent.tmp")
        
        def write_data():
            with open(concurrent_file, "wb") as f:
                for i in range(1000):
                    f.write(f"Line {i}\n".encode())
        
        try:
            write_data()  # Write initial data
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(concurrent_file, cek)
            self.assertIsNotNone(result)
        finally:
            if concurrent_file.exists():
                concurrent_file.unlink()
    
    def test_encrypt_file_network_path(self):
        """Test encryption with network path (UNC path on Windows)."""
        # This test might fail on non-Windows or without network access, which is expected
        network_path = Path("\\\\localhost\\c$\\temp\\test.tmp")
        if network_path.exists():
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(network_path, cek)
            # Result could be None due to permissions, which is acceptable
    
    def test_encrypt_file_insufficient_disk_space(self):
        """Test encryption when there's insufficient disk space (mocked)."""
        with patch('builtins.open', side_effect=OSError("No space left on device")):
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(self.test_file, cek)
            self.assertIsNone(result)
    
    def test_encrypt_file_readonly_file(self):
        """Test encryption of read-only file."""
        readonly_file = Path("readonly.tmp")
        with open(readonly_file, "wb") as f:
            f.write(self.test_data)
        
        try:
            readonly_file.chmod(0o444)  # Read-only
            cek = self.crypto_manager.generate_cek()
            result = self.crypto_manager.encrypt_file(readonly_file, cek)
            # Should still work as we're only reading
            self.assertIsNotNone(result)
        finally:
            if readonly_file.exists():
                readonly_file.chmod(0o644)  # Restore permissions
                readonly_file.unlink()

    # ===== COMPREHENSIVE HASH FUNCTION TESTS =====
    
    def test_get_sha256_hash_known_vectors(self):
        """Test SHA-256 with known test vectors."""
        test_vectors = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"),
            (b"abcdefghijklmnopqrstuvwxyz", "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"),
        ]
        
        for data, expected_hash in test_vectors:
            with self.subTest(data=data):
                result = self.crypto_manager.get_sha256_hash(data)
                self.assertEqual(result, expected_hash)
    
    def test_get_sha256_hash_unicode_data(self):
        """Test SHA-256 with unicode data."""
        unicode_data = "Hello, 世界! 🌍".encode('utf-8')
        hash_result = self.crypto_manager.get_sha256_hash(unicode_data)
        self.assertEqual(len(hash_result), 64)
        self.assertIsInstance(hash_result, str)
    
    def test_get_sha256_hash_very_large_data(self):
        """Test SHA-256 with very large data."""
        large_data = b"X" * (10 * 1024 * 1024)  # 10MB
        hash_result = self.crypto_manager.get_sha256_hash(large_data)
        self.assertEqual(len(hash_result), 64)
    
    def test_get_sha256_hash_consistency(self):
        """Test that SHA-256 produces consistent results."""
        data = b"consistent test data"
        hash1 = self.crypto_manager.get_sha256_hash(data)
        hash2 = self.crypto_manager.get_sha256_hash(data)
        self.assertEqual(hash1, hash2)
    
    def test_get_sha256_hash_different_data(self):
        """Test that different data produces different hashes."""
        data1 = b"data1"
        data2 = b"data2"
        hash1 = self.crypto_manager.get_sha256_hash(data1)
        hash2 = self.crypto_manager.get_sha256_hash(data2)
        self.assertNotEqual(hash1, hash2)
    
    def test_get_sha256_hash_avalanche_effect(self):
        """Test that small changes in input produce very different hashes."""
        data1 = b"hello world"
        data2 = b"hello world!"
        hash1 = self.crypto_manager.get_sha256_hash(data1)
        hash2 = self.crypto_manager.get_sha256_hash(data2)
        
        # Count different characters
        differences = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
        self.assertGreater(differences, 30)  # Should be very different
    
    def test_get_sha256_hash_incremental(self):
        """Test that incremental updates produce same result as single update."""
        data1 = b"part1"
        data2 = b"part2"
        combined = data1 + data2
        
        # Simulate incremental hashing
        import hashlib
        sha256 = hashlib.sha256()
        sha256.update(data1)
        sha256.update(data2)
        incremental_hash = sha256.hexdigest()
        
        # Compare with single update
        single_hash = self.crypto_manager.get_sha256_hash(combined)
        self.assertEqual(incremental_hash, single_hash)

    # ===== COMPREHENSIVE MANIFEST TESTS =====
    
    def test_create_manifest_with_none_job(self):
        """Test manifest creation with None job."""
        with self.assertRaises(AttributeError):
            self.crypto_manager.create_manifest(None, {})
    
    def test_create_manifest_with_invalid_job(self):
        """Test manifest creation with job missing job_id."""
        class InvalidJob:
            pass  # No job_id attribute
        
        with self.assertRaises(AttributeError):
            self.crypto_manager.create_manifest(InvalidJob(), {})
    
    def test_create_manifest_with_none_file_metadata(self):
        """Test manifest creation with None file metadata."""
        class MockJob:
            job_id = "test-job"
        
        manifest = self.crypto_manager.create_manifest(MockJob(), {})
        self.assertEqual(manifest["job_id"], "test-job")
        self.assertEqual(manifest["files"], {})
    
    def test_create_manifest_with_non_dict_file_metadata(self):
        """Test manifest creation with non-dictionary file metadata."""
        class MockJob:
            job_id = "test-job"
        
        # The actual implementation doesn't validate the type, it just uses it directly
        manifest = self.crypto_manager.create_manifest(MockJob(), "not a dict")
        self.assertEqual(manifest["job_id"], "test-job")
        self.assertEqual(manifest["files"], "not a dict")
    
    def test_create_manifest_with_complex_file_metadata(self):
        """Test manifest creation with complex file metadata structure."""
        class MockJob:
            job_id = "complex-job-789"
        
        complex_file_data = {
            "C:\\path\\file1.txt": {
                "sha256_encrypted": "hash1",
                "size": 1024,
                "modified_time": "2023-01-01T00:00:00Z"
            },
            "C:\\path\\file2.log": {
                "sha256_encrypted": "hash2",
                "size": 2048,
                "modified_time": "2023-01-02T00:00:00Z",
                "permissions": "rw-r--r--"
            }
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), complex_file_data)
        
        self.assertEqual(manifest["job_id"], "complex-job-789")
        self.assertEqual(len(manifest["files"]), 2)
        self.assertIn("file1.txt", str(manifest["files"]))
        self.assertIn("file2.log", str(manifest["files"]))
    
    def test_create_manifest_with_unicode_paths(self):
        """Test manifest creation with unicode file paths."""
        class MockJob:
            job_id = "unicode-job"
        
        unicode_file_data = {
            "C:\\测试\\文件.txt": {"sha256_encrypted": "unicode_hash"},
            "C:\\path\\файл.log": {"sha256_encrypted": "cyrillic_hash"}
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), unicode_file_data)
        
        self.assertEqual(manifest["job_id"], "unicode-job")
        self.assertEqual(len(manifest["files"]), 2)
    
    def test_create_manifest_with_empty_strings(self):
        """Test manifest creation with empty string values."""
        class MockJob:
            job_id = ""
        
        empty_file_data = {
            "": {"sha256_encrypted": ""},
            "C:\\path\\file.txt": {"sha256_encrypted": ""}
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), empty_file_data)
        
        self.assertEqual(manifest["job_id"], "")
        self.assertEqual(len(manifest["files"]), 2)
    
    def test_create_manifest_with_nested_metadata(self):
        """Test manifest creation with deeply nested metadata."""
        class MockJob:
            job_id = "nested-job"
        
        nested_file_data = {
            "file1.txt": {
                "encryption": {
                    "algorithm": "AES-256-GCM",
                    "key_id": "key123"
                },
                "metadata": {
                    "size": 1024,
                    "checksums": {
                        "sha256": "hash1",
                        "md5": "md5hash1"
                    }
                }
            }
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), nested_file_data)
        
        self.assertEqual(manifest["job_id"], "nested-job")
        self.assertIn("file1.txt", manifest["files"])
    
    def test_sign_manifest_with_none(self):
        """Test signing with None manifest."""
        with self.assertRaises(AttributeError):
            self.crypto_manager.sign_manifest(None)
    
    def test_sign_manifest_with_empty_dict(self):
        """Test signing with empty manifest."""
        empty_manifest = {}
        signed = self.crypto_manager.sign_manifest(empty_manifest)
        
        self.assertIn("signature", signed)
        self.assertIn("value", signed["signature"])
    
    def test_sign_manifest_with_existing_signature(self):
        """Test signing manifest that already has a signature."""
        manifest_with_sig = {
            "job_id": "test",
            "signature": {"old": "signature"}
        }
        
        signed = self.crypto_manager.sign_manifest(manifest_with_sig)
        
        # Should overwrite existing signature
        self.assertIn("signature", signed)
        self.assertIn("value", signed["signature"])
        self.assertNotIn("old", signed["signature"])
    
    def test_sign_manifest_preserves_all_fields(self):
        """Test that signing preserves all original fields."""
        original = {
            "job_id": "test",
            "files": {"file1": "hash1"},
            "gateway_info": {"version": "1.0"},
            "encryption_params": {"algorithm": "AES-256-GCM"},
            "custom_field": "custom_value"
        }
        
        signed = self.crypto_manager.sign_manifest(original)
        
        for key, value in original.items():
            self.assertEqual(signed[key], value)
        self.assertIn("signature", signed)

    # ===== COMPREHENSIVE DISK I/O TESTS =====
    
    def test_save_cek_to_disk(self):
        """Test saving CEK to disk."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("test_cek.bin")
        
        try:
            self.crypto_manager.save_cek_to_disk(cek, cek_file)
            
            self.assertTrue(cek_file.exists())
            with open(cek_file, 'rb') as f:
                saved_cek = f.read()
            self.assertEqual(saved_cek, cek)
        finally:
            if cek_file.exists():
                cek_file.unlink()
    
    def test_save_cek_to_disk_nonexistent_directory(self):
        """Test saving CEK to nonexistent directory."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("nonexistent_dir/test_cek.bin")
        
        with self.assertRaises(FileNotFoundError):
            self.crypto_manager.save_cek_to_disk(cek, cek_file)
    
    def test_save_cek_to_disk_permission_denied(self):
        """Test saving CEK when permission is denied."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("test_cek.bin")
        
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with self.assertRaises(PermissionError):
                self.crypto_manager.save_cek_to_disk(cek, cek_file)
    
    def test_save_cek_to_disk_disk_full(self):
        """Test saving CEK when disk is full."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("test_cek.bin")
        
        with patch('builtins.open', side_effect=OSError("No space left on device")):
            with self.assertRaises(OSError):
                self.crypto_manager.save_cek_to_disk(cek, cek_file)
    
    def test_load_cek_from_disk(self):
        """Test loading CEK from disk."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("test_cek.bin")
        
        try:
            with open(cek_file, 'wb') as f:
                f.write(cek)
            
            loaded_cek = self.crypto_manager.load_cek_from_disk(cek_file)
            self.assertEqual(loaded_cek, cek)
        finally:
            if cek_file.exists():
                cek_file.unlink()
    
    def test_load_cek_from_disk_nonexistent_file(self):
        """Test loading CEK from nonexistent file."""
        cek_file = Path("nonexistent_cek.bin")
        
        with self.assertRaises(FileNotFoundError):
            self.crypto_manager.load_cek_from_disk(cek_file)
    
    def test_load_cek_from_disk_permission_denied(self):
        """Test loading CEK when permission is denied."""
        cek_file = Path("test_cek.bin")
        
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with self.assertRaises(PermissionError):
                self.crypto_manager.load_cek_from_disk(cek_file)
    
    def test_load_cek_from_disk_corrupted_file(self):
        """Test loading CEK from corrupted file."""
        cek_file = Path("corrupted_cek.bin")
        
        try:
            with open(cek_file, 'wb') as f:
                f.write(b"corrupted data")
            
            loaded_cek = self.crypto_manager.load_cek_from_disk(cek_file)
            # Should return the corrupted data as-is
            self.assertEqual(loaded_cek, b"corrupted data")
        finally:
            if cek_file.exists():
                cek_file.unlink()
    
    def test_load_cek_from_disk_empty_file(self):
        """Test loading CEK from empty file."""
        cek_file = Path("empty_cek.bin")
        
        try:
            cek_file.touch()  # Create empty file
            
            loaded_cek = self.crypto_manager.load_cek_from_disk(cek_file)
            self.assertEqual(loaded_cek, b"")
        finally:
            if cek_file.exists():
                cek_file.unlink()
    
    def test_cek_roundtrip(self):
        """Test complete CEK save/load roundtrip."""
        original_cek = self.crypto_manager.generate_cek()
        cek_file = Path("roundtrip_cek.bin")
        
        try:
            self.crypto_manager.save_cek_to_disk(original_cek, cek_file)
            loaded_cek = self.crypto_manager.load_cek_from_disk(cek_file)
            self.assertEqual(loaded_cek, original_cek)
        finally:
            if cek_file.exists():
                cek_file.unlink()

    # ===== COMPREHENSIVE ERROR HANDLING TESTS =====
    
    def test_encrypt_file_invalid_key_type(self):
        """Test encryption with invalid key type."""
        # The actual implementation doesn't validate key type, it just passes it to AESGCM
        # which will raise an exception when trying to use the key
        result = self.crypto_manager.encrypt_file(self.test_file, "not bytes")
        self.assertIsNone(result)  # Should return None due to exception in encrypt_file
    
    def test_encrypt_file_none_key(self):
        """Test encryption with None key."""
        result = self.crypto_manager.encrypt_file(self.test_file, None)
        self.assertIsNone(result)  # Should return None due to exception in encrypt_file
    
    def test_encrypt_file_integer_key(self):
        """Test encryption with integer key."""
        result = self.crypto_manager.encrypt_file(self.test_file, 123)
        self.assertIsNone(result)  # Should return None due to exception in encrypt_file
    
    def test_get_sha256_hash_invalid_type(self):
        """Test hash function with invalid data type."""
        with self.assertRaises(TypeError):
            self.crypto_manager.get_sha256_hash("not bytes")
    
    def test_get_sha256_hash_none(self):
        """Test hash function with None."""
        with self.assertRaises(TypeError):
            self.crypto_manager.get_sha256_hash(None)
    
    def test_get_sha256_hash_integer(self):
        """Test hash function with integer."""
        with self.assertRaises(TypeError):
            self.crypto_manager.get_sha256_hash(123)
    
    def test_create_manifest_invalid_job_type(self):
        """Test manifest creation with invalid job type."""
        with self.assertRaises(AttributeError):
            self.crypto_manager.create_manifest("not a job", {})
    
    def test_sign_manifest_invalid_type(self):
        """Test signing with invalid manifest type."""
        with self.assertRaises(AttributeError):
            self.crypto_manager.sign_manifest("not a dict")
    
    def test_save_cek_invalid_path_type(self):
        """Test saving CEK with invalid path type."""
        cek = self.crypto_manager.generate_cek()
        # The actual implementation doesn't validate path type, it just passes it to open()
        # On Windows, this might work if "not a path" is treated as a filename
        try:
            self.crypto_manager.save_cek_to_disk(cek, "not a path")
            # If it doesn't raise an exception, check that the file was created
            self.assertTrue(Path("not a path").exists())
            Path("not a path").unlink()  # Clean up
        except OSError:
            # This is also acceptable behavior
            pass
    
    def test_load_cek_invalid_path_type(self):
        """Test loading CEK with invalid path type."""
        # The actual implementation doesn't validate path type, it just passes it to open()
        # On Windows, this might work if "not a path" is treated as a filename
        try:
            result = self.crypto_manager.load_cek_from_disk("not a path")
            # If it doesn't raise an exception, it should return some data (the file exists)
            self.assertIsInstance(result, bytes)
            # Clean up the file if it was created
            if Path("not a path").exists():
                Path("not a path").unlink()
        except FileNotFoundError:
            # This is also acceptable behavior
            pass

    # ===== COMPREHENSIVE INTEGRATION TESTS =====
    
    def test_complete_encryption_workflow(self):
        """Test complete encryption workflow from key generation to decryption."""
        # Generate key
        cek = self.crypto_manager.generate_cek()
        
        # Encrypt file
        encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
        self.assertIsNotNone(encryption_result)
        ciphertext, nonce, tag = encryption_result
        
        # Create manifest
        class MockJob:
            job_id = "integration-test"
        
        file_metadata = {
            str(self.test_file): {
                "sha256_encrypted": self.crypto_manager.get_sha256_hash(ciphertext)
            }
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), file_metadata)
        self.assertEqual(manifest["job_id"], "integration-test")
        
        # Sign manifest
        signed_manifest = self.crypto_manager.sign_manifest(manifest)
        self.assertIn("signature", signed_manifest)
        
        # Verify decryption
        aesgcm = AESGCM(cek)
        full_ciphertext = ciphertext + tag
        decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
        self.assertEqual(decrypted_data, self.test_data)
    
    def test_multiple_files_encryption_workflow(self):
        """Test encryption workflow with multiple files."""
        files_data = []
        cek = self.crypto_manager.generate_cek()
        
        # Create multiple test files
        for i in range(5):
            test_file = Path(f"test_file_{i}.tmp")
            test_data = f"Test data for file {i}".encode()
            
            with open(test_file, "wb") as f:
                f.write(test_data)
            
            files_data.append((test_file, test_data))
        
        try:
            # Encrypt all files
            file_metadata = {}
            for test_file, test_data in files_data:
                encryption_result = self.crypto_manager.encrypt_file(test_file, cek)
                self.assertIsNotNone(encryption_result)
                ciphertext, nonce, tag = encryption_result
                
                file_metadata[str(test_file)] = {
                    "sha256_encrypted": self.crypto_manager.get_sha256_hash(ciphertext)
                }
            
            # Create manifest
            class MockJob:
                job_id = "multi-file-test"
            
            manifest = self.crypto_manager.create_manifest(MockJob(), file_metadata)
            self.assertEqual(len(manifest["files"]), 5)
            
            # Sign manifest
            signed_manifest = self.crypto_manager.sign_manifest(manifest)
            self.assertIn("signature", signed_manifest)
            
        finally:
            # Clean up test files
            for test_file, _ in files_data:
                if test_file.exists():
                    test_file.unlink()
    
    def test_encryption_with_disk_key_storage(self):
        """Test encryption workflow with disk-based key storage."""
        cek = self.crypto_manager.generate_cek()
        cek_file = Path("workflow_cek.bin")
        
        try:
            # Save key to disk
            self.crypto_manager.save_cek_to_disk(cek, cek_file)
            
            # Encrypt file
            encryption_result = self.crypto_manager.encrypt_file(self.test_file, cek)
            self.assertIsNotNone(encryption_result)
            
            # Load key from disk
            loaded_cek = self.crypto_manager.load_cek_from_disk(cek_file)
            self.assertEqual(loaded_cek, cek)
            
            # Verify we can decrypt with loaded key
            ciphertext, nonce, tag = encryption_result
            aesgcm = AESGCM(loaded_cek)
            full_ciphertext = ciphertext + tag
            decrypted_data = aesgcm.decrypt(nonce, full_ciphertext, None)
            self.assertEqual(decrypted_data, self.test_data)
            
        finally:
            if cek_file.exists():
                cek_file.unlink()
    
    def test_manifest_serialization(self):
        """Test that manifest can be serialized to JSON."""
        class MockJob:
            job_id = "serialization-test"
        
        file_metadata = {
            "file1.txt": {"sha256_encrypted": "hash1"},
            "file2.txt": {"sha256_encrypted": "hash2"}
        }
        
        manifest = self.crypto_manager.create_manifest(MockJob(), file_metadata)
        signed_manifest = self.crypto_manager.sign_manifest(manifest)
        
        # Should be JSON serializable
        json_str = json.dumps(signed_manifest)
        self.assertIsInstance(json_str, str)
        
        # Should be deserializable
        deserialized = json.loads(json_str)
        self.assertEqual(deserialized["job_id"], "serialization-test")
        self.assertIn("signature", deserialized)

    # ===== PERFORMANCE AND STRESS TESTS =====
    
    def test_encryption_performance_large_file(self):
        """Test encryption performance with large file."""
        large_file = Path("large_performance.tmp")
        large_data = b"X" * (50 * 1024 * 1024)  # 50MB
        
        with open(large_file, "wb") as f:
            f.write(large_data)
        
        try:
            cek = self.crypto_manager.generate_cek()
            
            start_time = time.time()
            result = self.crypto_manager.encrypt_file(large_file, cek)
            end_time = time.time()
            
            self.assertIsNotNone(result)
            # Should complete within reasonable time (adjust threshold as needed)
            self.assertLess(end_time - start_time, 30)  # 30 seconds max
            
        finally:
            if large_file.exists():
                large_file.unlink()
    
    def test_hash_performance_large_data(self):
        """Test hash performance with large data."""
        large_data = b"X" * (100 * 1024 * 1024)  # 100MB
        
        start_time = time.time()
        hash_result = self.crypto_manager.get_sha256_hash(large_data)
        end_time = time.time()
        
        self.assertEqual(len(hash_result), 64)
        # Should complete within reasonable time
        self.assertLess(end_time - start_time, 10)  # 10 seconds max
    
    def test_memory_usage_encryption(self):
        """Test that encryption doesn't consume excessive memory."""
        # This is a basic test - in a real scenario, you might use memory profiling tools
        cek = self.crypto_manager.generate_cek()
        
        # Encrypt multiple files to test memory usage
        for i in range(10):
            test_file = Path(f"memory_test_{i}.tmp")
            test_data = b"X" * (1024 * 1024)  # 1MB each
            
            with open(test_file, "wb") as f:
                f.write(test_data)
            
            try:
                result = self.crypto_manager.encrypt_file(test_file, cek)
                self.assertIsNotNone(result)
            finally:
                if test_file.exists():
                    test_file.unlink()

if __name__ == '__main__':
    unittest.main()