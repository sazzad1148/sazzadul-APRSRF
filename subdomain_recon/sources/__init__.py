"""
Auto-discovers every Source subclass defined in this package. Dropping a new
`my_source.py` file here with a Source subclass is enough for it to show up
in the registry -- no core pipeline code needs to change.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil

from .base import Source, SourceContext  # noqa: F401  (re-exported)

_REGISTRY: dict[str, type] = {}


def _discover():
    package_name = __name__
    package_path = __path__
    for _, module_name, _ in pkgutil.iter_modules(package_path):
        if module_name in ("base",):
            continue
        module = importlib.import_module(f"{package_name}.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Source) and obj is not Source:
                instance = obj()
                _REGISTRY[instance.name] = obj


_discover()


def all_sources() -> dict:
    return dict(_REGISTRY)


def get_source(name: str):
    cls = _REGISTRY.get(name)
    return cls() if cls else None


def instantiate_all():
    return {name: cls() for name, cls in _REGISTRY.items()}
