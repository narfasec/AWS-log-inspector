# import pkgutil, os
# import modules

# pkgpath = os.path.dirname(modules.__file__)
# print([name for _, name, _ in pkgutil.iter_modules([pkgpath])])

import importlib.util
from pathlib import Path
import os
MODULE_EXTENSIONS = '.py'

def package_contents(package_name):
    spec = importlib.util.find_spec(package_name)
    if spec is None:
        return set()

    pathname = str(Path(spec.origin).parent)
    ret = set()
    with os.scandir(pathname) as entries:
        for entry in entries:
            if entry.name.startswith('__'):
                continue
            current = '.'.join((package_name, entry.name.partition('.')[0]))
            if entry.is_file():
                if entry.name.endswith(MODULE_EXTENSIONS):
                    ret.add(current)
            elif entry.is_dir():
                ret.add(current)
                ret |= package_contents(current)


    return ret

package_contents('modules')