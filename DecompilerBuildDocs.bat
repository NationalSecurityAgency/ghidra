SET OLDDIR=%CD%
SET OLDPATH=%PATH%
SET PATH=C:\MinGW\bin;%PATH%
CD Ghidra\Features\Decompiler\src\decompile\cpp
mingw32-make doc
SET PATH=%OLDPATH%
CD %OLDDIR%
Ghidra\Features\Decompiler\src\decompile\doc\html\index.html