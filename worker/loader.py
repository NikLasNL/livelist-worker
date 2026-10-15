"""
worker/loader.py — динамическая загрузка Python-модулей.
"""

import importlib.util
import sys
import traceback
from pathlib import Path


class ModuleLoader:
    def __init__(self, modules_dir: Path):
        self.modules_dir = Path(modules_dir)
        self.loaded = {}

    def list_modules(self):
        return [f.stem for f in self.modules_dir.glob("*.py")
                if not f.name.startswith("_")]

    def load_module(self, name):
        path = self.modules_dir / f"{name}.py"
        if not path.exists():
            raise FileNotFoundError(f"Module not found: {path}")

        if name in self.loaded:
            del self.loaded[name]
            mod_key = f"worker_mod_{name}"
            if mod_key in sys.modules:
                del sys.modules[mod_key]

        mod_key = f"worker_mod_{name}"
        spec = importlib.util.spec_from_file_location(mod_key, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_key] = mod

        try:
            spec.loader.exec_module(mod)
        except Exception:
            traceback.print_exc()
            del sys.modules[mod_key]
            raise

        self.loaded[name] = mod
        return mod

    def reload_all(self):
        for name in list(self.loaded.keys()):
            try:
                self.load_module(name)
            except Exception as e:
                print(f"[!] Reload {name}: {e}")

    def get(self, name):
        return self.loaded.get(name)