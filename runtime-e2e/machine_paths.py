# SPDX-License-Identifier: Apache-2.0
"""Host paths of the harness tools come from environment variables, never from one machine's layout.

``env_path(name, what)`` returns the variable's value as a Path. An unset (or empty) variable gives an ``UnsetPath``: importing a
module and building a config with it still work, and the first real use of the path (``str()``, ``/``, ``open()``, ``.read_text()``,
...) raises ``contracts.Violation`` with a message that names the variable and what it is for, so a caller that turns a
Violation into a refused result (a nightly entry recorded INCONCLUSIVE) does so for a missing path too. Each module documents the
variables it reads.
"""
import os
from pathlib import Path

from contracts import Violation


class UnsetPath(os.PathLike):
    """A required host path whose environment variable is not set: any use of it refuses, naming the variable."""

    def __init__(self, name, what):
        self.name, self.what = name, what

    def refuse(self, *_args, **_kwargs):
        raise Violation(f'{self.name} is not set: set it to {self.what}')

    __fspath__ = __str__ = __truediv__ = __rtruediv__ = refuse

    def __getattr__(self, attr):
        if attr.startswith('__'):
            raise AttributeError(attr)
        self.refuse()

    def __repr__(self):
        return f'UnsetPath({self.name!r})'

    def __eq__(self, other):
        return isinstance(other, UnsetPath) and other.name == self.name

    def __hash__(self):
        return hash(('UnsetPath', self.name))


def env_path(name, what, env=None):
    """``Path($name)``, or an ``UnsetPath`` that refuses on first use when the variable is unset or empty."""
    value = (os.environ if env is None else env).get(name)
    return Path(value) if value else UnsetPath(name, what)


def recorded(path):
    """The path as evidence text: ``str(path)``, or None for an unset one (recording a setting never requires it)."""
    return None if isinstance(path, UnsetPath) else str(path)
