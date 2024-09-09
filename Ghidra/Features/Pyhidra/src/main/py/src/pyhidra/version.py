
import dataclasses
from datetime import datetime
from pathlib import Path
import re


MINIMUM_GHIDRA_VERSION = "11.2"
_APPLICATION_PATTERN = re.compile(r"^application\.(\S+?)=(.*)$")


@dataclasses.dataclass(frozen=True)
class ApplicationInfo:
    """
    Ghidra Application Properties
    """
    name: str
    version: str
    release_name: str
    revision_ghidra: str = ""
    build_date: str = ""
    build_date_short: str = ""
    layout_version: str = ""
    gradle_min: str = ""
    java_min: str = ""
    java_max: str = ""
    java_compiler: str = ""
    gradle_max: str = ""

    @classmethod
    def from_file(cls, file: Path):
        """
        Parses Ghidra's application.properties file from the provided path
        """
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        kwargs = dict()
        for line in file.read_text(encoding="utf8").splitlines():
            match = _APPLICATION_PATTERN.match(line)
            if not match:
                continue
            attr = match.group(1).replace('.', '_').replace('-', '_')
            value = match.group(2)
            if attr in valid_fields:
                kwargs[attr] = value
        return cls(**kwargs)


@dataclasses.dataclass
class ExtensionDetails:
    """
    Python side ExtensionDetails
    """
    name: str
    description: str
    author: str
    createdOn: str = dataclasses.field(default_factory=lambda: str(datetime.now()))
    version: str = None
    plugin_version: str = "0.0.1"

    @classmethod
    def from_file(cls, ext_path: Path):
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        def cast(key, value):
            return cls.__annotations__[key](value)
        lines = ext_path.read_text().splitlines()
        kwargs = {
            key: cast(key, value)
            for key, value in map(lambda l: l.split("="), lines)
            if key in valid_fields
        }
        return cls(**kwargs)

    def __repr__(self):
        return "\n".join(f"{key}={value}" for key, value in dataclasses.asdict(self).items())
