PDB.EXE

The PDB.EXE executable delivered with Ghidra has been built with Visual Studio 2017 and has a
dependency on the msdia140.dll in order to execute and process PDB files.  

If it is necessary to rebuild the PDB.exe using a newer version of of the SDK, this can be done by 
using the included Visual Studio project to rebuild the executable.  After opening the project
solution file within Visual Studio simply re-target the solution to a new version of the SDK. 
This can be accomplished by opening the solution file within Visual Studio, right-clicking on 
the Solution 'pdb' node and selecting the "Re-target solution" menu item.  After re-targeting 
the solution simply rebuild it to produce a new executable (Ghidra/Features/PDB/os/win64/pdb.exe).
You may also need to adjust the solution configuration to build the pdb project when the 
solution is built. 

NOTES:

Registration of DIA SDK DLL required! (see docs/README_PDB.html file).

   