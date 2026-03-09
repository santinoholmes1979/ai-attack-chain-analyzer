import json
from pathlib import Path


def load_events(file_path):

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Event file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)