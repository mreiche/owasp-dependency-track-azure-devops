from pathlib import Path

from dotenv import load_dotenv

cwd = Path(__file__)

def setup_module():
    assert load_dotenv(cwd.parent / "test.env")
