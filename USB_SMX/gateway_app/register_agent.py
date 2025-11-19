import sys
import json
import argparse
from pathlib import Path

def register_agent(agent_id: str, public_key_file: Path, registry_file: Path):
    """
    Registers a new agent by adding its public key content to the gateway's key registry.
    """
    if not public_key_file.exists():
        print(f"Error: Public key file not found at {public_key_file}")
        return

    print(f"Registering agent '{agent_id}' with public key from {public_key_file}")

    # Read the public key content
    try:
        public_key_pem = public_key_file.read_text()
    except Exception as e:
        print(f"Error reading public key file: {e}")
        return

    # Load existing registry or create a new one
    if registry_file.exists():
        try:
            with open(registry_file, 'r') as f:
                registry = json.load(f)
            if "agents" not in registry:
                registry["agents"] = []
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not read existing registry file at {registry_file}. A new one will be created. Error: {e}")
            registry = {"agents": []}
    else:
        registry = {"agents": []}
        # Ensure the parent directory exists
        registry_file.parent.mkdir(parents=True, exist_ok=True)

    # Check if agent ID already exists
    for i, agent in enumerate(registry["agents"]):
        if agent.get("id") == agent_id:
            print(f"Agent '{agent_id}' already exists. Updating its public key.")
            registry["agents"][i]["public_key_pem"] = public_key_pem
            break
    else: # 'for...else' loop: this runs if the loop completes without a 'break'
        print(f"Adding new agent '{agent_id}' to registry.")
        registry["agents"].append({
            "id": agent_id,
            "public_key_pem": public_key_pem
        })

    # Write the updated registry back to the file
    try:
        with open(registry_file, 'w') as f:
            json.dump(registry, f, indent=2)
        print(f"Successfully updated agent registry at {registry_file}")
    except Exception as e:
        print(f"Error writing to registry file: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Register an agent's public key with the gateway.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("agent_id", type=str, help="A unique identifier for the agent (e.g., 'agent_3').")
    parser.add_argument("public_key_path", type=str, help="The path to the agent's public key PEM file (e.g., from a USB drive).")
    
    args = parser.parse_args()

    registry_path = Path(__file__).parent / "src/gateway/keys/agent_key_registry.json"
    
    try:
        key_file_path = Path(args.public_key_path)
        register_agent(args.agent_id, key_file_path, registry_path)
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
