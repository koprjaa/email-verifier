#
# Project: email-verifier
# File:    conftest.py
#
# Description:
# Test setup that keeps the suite off the network.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

"""Keep the tests off the network.

verifier/__init__.py imports EmailVerifier, which needs aiodns and an event
loop it cannot get on Windows. The classify module has no such dependency, so
it is loaded from its file instead of through the package.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if "verifier.classify" not in sys.modules:
    _load("verifier.classify", ROOT / "verifier" / "classify.py")
