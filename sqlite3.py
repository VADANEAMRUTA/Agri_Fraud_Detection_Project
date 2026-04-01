"""Expose the standard-library sqlite3 package from the project root."""

from pathlib import Path
import sysconfig


_package_dir = Path(sysconfig.get_path("stdlib")) / "sqlite3"
__path__ = [str(_package_dir)]
__package__ = "sqlite3"
__file__ = str(_package_dir / "__init__.py")

with open(__file__, "r", encoding="utf-8") as _sqlite3_init:
    exec(compile(_sqlite3_init.read(), __file__, "exec"), globals(), globals())

