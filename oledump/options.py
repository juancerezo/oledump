from typing import TypedDict
from pathlib import Path


class OleDumpOptions(TypedDict):
    vdadecompress: bool
    vbadecompresscorrupt: bool
    vbadecompressskipattributes: bool
    plugins: list[str]
    pluginoptions: str
    plugindir: Path
    decoders: list[str]
    decoderdir: Path | None
    raw: bool
    verbose: bool
    quiet: bool
    jsonoutput: bool
    yara: Path | None
    password: str
    find: str
    select: str