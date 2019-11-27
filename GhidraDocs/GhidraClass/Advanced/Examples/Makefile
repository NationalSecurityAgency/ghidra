CC=gcc
CXX=g++
AS=gcc

OUTDIR := out

EXAMPLES := dataMutability override custom switch sharedReturn jumpWithinInstruction opaque globalRegVars.so setRegister compilerVsDecompiler noReturn createStructure animals ldiv inline write

$(EXAMPLES): | $(OUTDIR)

$(OUTDIR):
	mkdir -p $(OUTDIR)

all: $(EXAMPLES)

dataMutability: dataMutability.c
	$(CC) dataMutability.c -o $(OUTDIR)/dataMutability -O2 

override: override.c
	$(CC) override.c -o $(OUTDIR)/override.so -shared -fPIC -O2

custom: custom.c
	$(CC) custom.c -o $(OUTDIR)/custom -fomit-frame-pointer 

switch: switch.s
	$(AS) switch.s -o $(OUTDIR)/switch 

jumpWithinInstruction: jumpWithinInstruction.c
	$(CC) jumpWithinInstruction.c -o $(OUTDIR)/jumpWithinInstruction -O2 -fno-inline

sharedReturn: sharedReturn.c
	$(CC) sharedReturn.c -o $(OUTDIR)/sharedReturn -O2 -fno-inline
	strip -s $(OUTDIR)/sharedReturn

opaque: opaque.c
	$(CC) opaque.c -o $(OUTDIR)/opaque -O2

globalRegVars.so: globalRegVars.c
	$(CC) globalRegVars.c -o $(OUTDIR)/globalRegVars.so -fPIC -shared -O2

setRegister: setRegister.c
	$(CC) setRegister.c -o $(OUTDIR)/setRegister -O2 -fno-inline

compilerVsDecompiler: compilerVsDecompiler.s
	$(AS) compilerVsDecompiler.s -o $(OUTDIR)/compilerVsDecompiler  

noReturn: noReturn.c
	$(CC) noReturn.c -o $(OUTDIR)/noReturn -shared -fPIC

createStructure: createStructure.c
	$(CC) createStructure.c -o $(OUTDIR)/createStructure -shared -fPIC -O2

animals: animals.cpp
	$(CXX) animals.cpp -o $(OUTDIR)/animals -O2 -std=c++11 

ldiv: ldiv.c
	$(CC) ldiv.c -o $(OUTDIR)/ldiv -O2

inline: inline.s
	$(AS) inline.s -o $(OUTDIR)/inline

write: write.c
	$(CC) write.c -o $(OUTDIR)/write -O1

clean:
	rm -rf $(OUTDIR)
