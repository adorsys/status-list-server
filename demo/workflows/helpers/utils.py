from pathlib import Path
from dotenv import dotenv_values

def get_base_url():
    """
    Discovers the base URL for the server based on a .env file at the project root.

    If a PORT variable is found in the .env file, it returns "http://localhost:PORT".
    Otherwise, it defaults to "http://localhost:8000".

    Returns:
        str: The determined base URL (e.g., "http://localhost:8000").
    """
    # Navigate to the project root
    workflows_dir = Path(__file__).parent.parent
    project_root = workflows_dir.parent.parent

    # Path to the .env file at the root
    dotenv_path = project_root / '.env'

    # Load the .env file - will load if it exists at the specified path
    dotenv_vars = dotenv_values(dotenv_path)

    # Get the PORT variable from the loaded env vars
    port = dotenv_vars.get("PORT", 8000)

    # Construct the base URL
    base_url = f"http://localhost:{port}"

    return base_url
