
import sys
import queue
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent_device_manager import AgentDeviceManager
from agent_file_processor import AgentFileProcessor
from agent_gui import GuiManager

def main():
    """Initializes and runs the agent portal."""
    print("--- SMX Agent Portal ---")
    
    gui_queue = queue.Queue()
    file_processor = AgentFileProcessor()
    gui_manager = GuiManager(gui_queue, file_processor)
    device_manager = AgentDeviceManager(gui_queue)
    
    device_manager.start_monitoring()
    
    print("Monitoring for processed USB devices...")

    try:
        gui_manager.start()
    except KeyboardInterrupt:
        print("Shutdown signal received.")
    finally:
        print("Stopping monitor...")
        device_manager.stop_monitoring()
        print("Agent Portal stopped.")

if __name__ == '__main__':
    main()
