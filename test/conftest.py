"""Keep generated Hypothesis state with the project's other disposable caches."""

from pathlib import Path

from hypothesis.configuration import set_hypothesis_home_dir

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / ".tmp" / "hypothesis")


class JsonResponse:
    """In-memory streaming HTTP response for network boundary tests."""

    def __init__(self, *, json, raise_for_status=lambda: None):
        self.json = json
        self.raise_for_status = raise_for_status
        self.status_code = 200
        self.closed = False

    def iter_content(self, chunk_size):
        import json

        data = json.dumps(self.json()).encode()
        for offset in range(0, len(data), chunk_size):
            yield data[offset : offset + chunk_size]

    def close(self):
        self.closed = True
