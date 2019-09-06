See the example emulation scripts contained within Ghidra/Features/Base/ghidra_scripts.

Sample scripts deobExampleX86 and deobHookExampleX86 may be built under Linux.

	cc -std=c99 -Wimplicit-function-declaration -o deobExampleX86 deobExample.c 
	cc -std=c99 -Wimplicit-function-declaration -o deobHookExampleX86 deobHookExample.c 
	
Once these examples have been compiled they may be imported into a Ghidra project and the
corresponding Ghidra Scripts (EmuX86DeobfuscateExampleScript and EmuX86GccDeobfuscateHookExampleScript) 
used to demonstrate the use of the EmulatorHelper class. 
