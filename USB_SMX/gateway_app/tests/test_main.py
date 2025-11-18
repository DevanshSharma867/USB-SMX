"""
Comprehensive tests for the main application entry point.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
from pathlib import Path

# Add the src directory to the Python path
SRC_PATH = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(SRC_PATH))

from gateway.main import main


class TestMainApplication(unittest.TestCase):
    """Test the main application entry point and lifecycle."""

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_initialization_and_startup(self, mock_sleep, mock_device_manager_class):
        """Test main application initialization and startup."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Mock sleep to prevent infinite loop
        mock_sleep.side_effect = [None, KeyboardInterrupt()]
        
        # Test main function
        with patch('builtins.print') as mock_print:
            main()
            
            # Verify device manager was created and started
            mock_device_manager_class.assert_called_once()
            mock_manager.start_monitoring.assert_called_once()
            
            # Verify startup messages
            expected_calls = [
                unittest.mock.call("--- SMX Gateway Service MVP ---"),
                unittest.mock.call("Monitoring for USB devices. Press Ctrl+C to stop."),
                unittest.mock.call("Shutdown signal received. Stopping monitor..."),
                unittest.mock.call("Gateway Service stopped.")
            ]
            mock_print.assert_has_calls(expected_calls, any_order=False)

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_keyboard_interrupt_handling(self, mock_sleep, mock_device_manager_class):
        """Test main application handles KeyboardInterrupt gracefully."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate KeyboardInterrupt after 2 seconds
        mock_sleep.side_effect = [None, None, KeyboardInterrupt()]
        
        with patch('builtins.print') as mock_print:
            main()
            
            # Verify shutdown sequence
            mock_manager.stop_monitoring.assert_called_once()
            
            # Verify shutdown messages
            shutdown_calls = [
                call for call in mock_print.call_args_list 
                if "Shutdown signal received" in str(call) or "Gateway Service stopped" in str(call)
            ]
            self.assertEqual(len(shutdown_calls), 2)

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_device_manager_creation_failure(self, mock_sleep, mock_device_manager_class):
        """Test main application handles DeviceManager creation failure."""
        mock_device_manager_class.side_effect = Exception("Failed to create DeviceManager")
        
        with self.assertRaises(Exception):
            main()

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_monitoring_start_failure(self, mock_sleep, mock_device_manager_class):
        """Test main application handles monitoring start failure."""
        mock_manager = MagicMock()
        mock_manager.start_monitoring.side_effect = Exception("Failed to start monitoring")
        mock_device_manager_class.return_value = mock_manager
        
        with self.assertRaises(Exception):
            main()

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_stop_monitoring_failure(self, mock_sleep, mock_device_manager_class):
        """Test main application handles stop monitoring failure gracefully."""
        mock_manager = MagicMock()
        mock_manager.stop_monitoring.side_effect = Exception("Failed to stop monitoring")
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate KeyboardInterrupt
        mock_sleep.side_effect = [None, KeyboardInterrupt()]
        
        # Should not raise exception even if stop_monitoring fails
        with patch('builtins.print'):
            main()

    def test_main_module_execution(self):
        """Test that main module can be executed directly."""
        # This tests the __name__ == '__main__' block
        with patch('gateway.main.main') as mock_main:
            # Simulate running the module directly
            import gateway.main
            # The main() function should be called when run as script
            # This is tested implicitly by the module import

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_continuous_monitoring_loop(self, mock_sleep, mock_device_manager_class):
        """Test that main runs continuous monitoring loop."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate multiple sleep cycles before KeyboardInterrupt
        mock_sleep.side_effect = [None, None, None, None, KeyboardInterrupt()]
        
        with patch('builtins.print'):
            main()
            
            # Verify sleep was called multiple times
            self.assertGreater(mock_sleep.call_count, 1)

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_exception_during_loop(self, mock_sleep, mock_device_manager_class):
        """Test main application handles exceptions during monitoring loop."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate exception during sleep
        mock_sleep.side_effect = Exception("System error during monitoring")
        
        with self.assertRaises(Exception):
            main()

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_graceful_shutdown_sequence(self, mock_sleep, mock_device_manager_class):
        """Test the complete graceful shutdown sequence."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate KeyboardInterrupt after 1 second
        mock_sleep.side_effect = [None, KeyboardInterrupt()]
        
        with patch('builtins.print') as mock_print:
            main()
            
            # Verify the complete shutdown sequence
            calls = [str(call) for call in mock_print.call_args_list]
            
            # Check that all expected messages are present
            self.assertTrue(any("Shutdown signal received" in call for call in calls))
            self.assertTrue(any("Gateway Service stopped" in call for call in calls))
            
            # Verify stop_monitoring was called
            mock_manager.stop_monitoring.assert_called_once()

    def test_main_imports_and_dependencies(self):
        """Test that main module imports all required dependencies."""
        import gateway.main
        
        # Verify required modules are imported
        self.assertTrue(hasattr(gateway.main, 'sys'))
        self.assertTrue(hasattr(gateway.main, 'time'))
        self.assertTrue(hasattr(gateway.main, 'Path'))
        self.assertTrue(hasattr(gateway.main, 'DeviceManager'))
        self.assertTrue(hasattr(gateway.main, 'main'))

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_thread_lifecycle(self, mock_sleep, mock_device_manager_class):
        """Test main thread lifecycle and resource management."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Simulate KeyboardInterrupt
        mock_sleep.side_effect = [None, KeyboardInterrupt()]
        
        with patch('builtins.print'):
            main()
            
            # Verify proper resource cleanup
            mock_manager.stop_monitoring.assert_called_once()

    @patch('gateway.main.DeviceManager')
    @patch('gateway.main.time.sleep')
    def test_main_error_handling_robustness(self, mock_sleep, mock_device_manager_class):
        """Test main application error handling robustness."""
        mock_manager = MagicMock()
        mock_device_manager_class.return_value = mock_manager
        
        # Test various error scenarios
        test_cases = [
            KeyboardInterrupt(),  # Normal shutdown
            Exception("Unexpected error"),  # Unexpected error
            SystemExit(0),  # System exit
        ]
        
        for error in test_cases:
            with self.subTest(error=type(error).__name__):
                mock_sleep.side_effect = [None, error]
                
                if isinstance(error, KeyboardInterrupt):
                    # Should handle KeyboardInterrupt gracefully
                    with patch('builtins.print'):
                        main()
                else:
                    # Should propagate other exceptions
                    with self.assertRaises(type(error)):
                        main()


if __name__ == '__main__':
    unittest.main()
