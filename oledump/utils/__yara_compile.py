from pathlib import Path

import yara

def yara_compile(path: Path):
    if path.is_dir():
        return yara.compile(filepaths={str(p): str(p) for p in path.iterdir()}, externals={'streamname': '', 'VBA': False})
    
    return yara.compile(filepath=str(path), externals={'streamname': '', 'VBA': False})