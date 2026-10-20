"""Keep generated Hypothesis state with the project's other disposable caches."""

from pathlib import Path

from hypothesis.configuration import set_hypothesis_home_dir

set_hypothesis_home_dir(Path(__file__).resolve().parents[1] / ".tmp" / "hypothesis")
