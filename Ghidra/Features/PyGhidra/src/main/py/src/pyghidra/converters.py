
from pathlib import Path

from jpype import JConversion, JClass


@JConversion("java.lang.String", instanceof=Path)
def pathToString(cls: JClass, path: Path):
    return cls(path.resolve().__str__())


@JConversion("java.io.File", instanceof=Path)
def pathToFile(cls: JClass, path: Path):
    return cls(path)
