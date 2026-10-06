import os
import threading

import pytest

from lab_api.main import create_server
from authpath.config import load_scenario

SCENARIO_PATH = os.path.join(
    os.path.dirname(__file__), "..", "policies", "lab_scenario.json"
)


@pytest.fixture
def lab():
    """Start a Lab API on a free port in a background thread: lab('patched')."""

    servers = []

    def start(mode: str) -> str:
        server = create_server(port=0, mode=mode, quiet=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start

    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def scenario_for():
    """scenario_for(base_url) -> the lab scenario pointed at that URL."""

    def build(base_url: str):
        return load_scenario(SCENARIO_PATH, base_url=base_url)

    return build
