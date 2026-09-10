/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Smoke test for the sla library: disassemble and translate a few fixed
// instructions with a compiled .sla file, print one deterministic text block
// and optionally compare it with an expected file.
//
//   sleigh_smoke <sleigh-home> <case> [--expect <file>]
//
// <sleigh-home> is the root that holds Ghidra/Processors/<P>/data/languages.
// <case> is one of: x86-64, arm-thumb, aarch64.
//
// Output format, one instruction per block:
//
//   <hex address> <mnemonic> <operands>
//     [<out>] = <opcode> <in>...     one line per p-code op, where a varnode
//                                    prints as <space>[<hex offset>:<size>]
//
// The program mirrors sleighexample.cc: an in-memory LoadImage, a
// ContextInternal, a Sleigh translator initialized from a DocumentStorage,
// and AssemblyEmit/PcodeEmit subclasses.  It only uses the sla archive.

#include "loadimage.hh"
#include "sleigh.hh"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using namespace ghidra;
using std::cerr;
using std::cout;

struct ContextSetting {
  const char *name;
  uintm value;
};

struct SmokeCase {
  const char *name;
  const char *slafile;		// Relative to the sleigh home
  uintb base;			// Load address of the bytes
  const uint1 *bytes;
  int4 length;
  const ContextSetting *context;
  int4 numContext;
};

// push rbp; mov rbp,rsp; mov [rbp-4],edi; mov eax,[rbp-4]; add eax,1; pop rbp; ret
const uint1 x86_64_bytes[] = {
  0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x5d, 0xc3
};
// x86-64.pspec context_data defaults
const ContextSetting x86_64_context[] = {
  { "addrsize", 2 }, { "opsize", 1 }, { "rexprefix", 0 }, { "longMode", 1 }
};

// push {r4,r5,lr}; adds r0,#1; pop {r4,r5,pc}
const uint1 arm_thumb_bytes[] = { 0x70, 0xb5, 0x01, 0x30, 0x70, 0xbd };
const ContextSetting arm_thumb_context[] = { { "TMode", 1 }, { "LRset", 0 } };

// stp x29,x30,[sp,#-16]!; mov x29,sp; add x0,x0,#1; ldp x29,x30,[sp],#16; ret
const uint1 aarch64_bytes[] = {
  0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x00, 0x04, 0x00, 0x91,
  0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6
};

const SmokeCase cases[] = {
  { "x86-64", "Ghidra/Processors/x86/data/languages/x86-64.sla", 0x401000,
    x86_64_bytes, sizeof(x86_64_bytes), x86_64_context, 4 },
  { "arm-thumb", "Ghidra/Processors/ARM/data/languages/ARM8_le.sla", 0x8000,
    arm_thumb_bytes, sizeof(arm_thumb_bytes), arm_thumb_context, 2 },
  { "aarch64", "Ghidra/Processors/AARCH64/data/languages/AARCH64.sla", 0x400000,
    aarch64_bytes, sizeof(aarch64_bytes), (const ContextSetting *)0, 0 },
};

const int4 numCases = sizeof(cases) / sizeof(cases[0]);

/// Bytes held in memory; anything outside the window reads as zero.
class MemoryLoadImage : public LoadImage {
  uintb baseaddr;
  int4 length;
  const uint1 *data;
public:
  MemoryLoadImage(uintb ad,const uint1 *ptr,int4 sz) : LoadImage("nofile") { baseaddr = ad; data = ptr; length = sz; }
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
  virtual string getArchType(void) const { return "memory"; }
  virtual void adjustVma(long adjust) { }
};

void MemoryLoadImage::loadFill(uint1 *ptr,int4 size,const Address &addr)

{
  uintb start = addr.getOffset();
  uintb max = baseaddr + (length - 1);
  for(int4 i=0;i<size;++i) {
    uintb curoff = start + i;
    if ((curoff < baseaddr) || (curoff > max)) {
      ptr[i] = 0;
      continue;
    }
    ptr[i] = data[(int4)(curoff - baseaddr)];
  }
}

class AssemblyPrinter : public AssemblyEmit {
  ostream &s;
public:
  AssemblyPrinter(ostream &str) : s(str) {}
  virtual void dump(const Address &addr,const string &mnem,const string &body) {
    s << "0x" << hex << addr.getOffset() << ' ' << mnem;
    if (!body.empty())
      s << ' ' << body;
    s << '\n';
  }
};

class PcodePrinter : public PcodeEmit {
  ostream &s;
  const AddrSpace *defaultCodeSpace;
  void printVarnode(const VarnodeData &data) {
    // LOAD and STORE encode their address space as the host pointer to an
    // AddrSpace in a constant varnode.  That pointer is intentionally not
    // stable across processes, so render the semantic space name instead.
    if (data.space->getType() == IPTR_CONSTANT &&
        data.offset == reinterpret_cast<uintb>(defaultCodeSpace)) {
      s << "spaceid[" << defaultCodeSpace->getName() << ']';
      return;
    }
    s << data.space->getName() << "[0x" << hex << data.offset << ':' << dec << data.size << ']';
  }
public:
  PcodePrinter(ostream &str,const AddrSpace *codeSpace) : s(str), defaultCodeSpace(codeSpace) {}
  virtual void dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize) {
    s << "  ";
    if (outvar != (VarnodeData *)0) {
      printVarnode(*outvar);
      s << " = ";
    }
    s << get_opname(opc);
    for(int4 i=0;i<isize;++i) {
      s << ' ';
      printVarnode(vars[i]);
    }
    s << '\n';
  }
};

const SmokeCase *findCase(const string &name)

{
  for(int4 i=0;i<numCases;++i) {
    if (name == cases[i].name)
      return &cases[i];
  }
  return (const SmokeCase *)0;
}

void runCase(const string &sleighhome,const SmokeCase &sc,ostream &out)

{
  MemoryLoadImage loader(sc.base,sc.bytes,sc.length);
  ContextInternal context;
  Sleigh trans(&loader,&context);

  string path = sleighhome;
  if (path.empty() || path[path.size()-1] != '/')
    path += '/';
  path += sc.slafile;
  istringstream sleighdoc("<sleigh>" + path + "</sleigh>");
  DocumentStorage docstorage;
  Element *sleighroot = docstorage.parseDocument(sleighdoc)->getRoot();
  docstorage.registerTag(sleighroot);
  trans.initialize(docstorage);

  for(int4 i=0;i<sc.numContext;++i)
    context.setVariableDefault(sc.context[i].name,sc.context[i].value);

  AssemblyPrinter asmemit(out);
  PcodePrinter pcodeemit(out,trans.getDefaultCodeSpace());
  Address addr(trans.getDefaultCodeSpace(),sc.base);
  Address lastaddr(trans.getDefaultCodeSpace(),sc.base + sc.length);
  while(addr < lastaddr) {
    trans.printAssembly(asmemit,addr);
    int4 length = trans.oneInstruction(pcodeemit,addr);
    addr = addr + length;
  }
}

int usage(const char *prog)

{
  cerr << "USAGE: " << prog << " <sleigh-home> <case> [--expect <file>]" << endl;
  cerr << "cases:";
  for(int4 i=0;i<numCases;++i)
    cerr << ' ' << cases[i].name;
  cerr << endl;
  return 2;
}

} // End anonymous namespace

int main(int argc,char **argv)

{
  using namespace ghidra;
  using std::cerr;
  using std::cout;

  if (argc != 3 && argc != 5)
    return usage(argv[0]);
  string sleighhome(argv[1]);
  string casename(argv[2]);
  string expectfile;
  if (argc == 5) {
    if (strcmp(argv[3],"--expect") != 0)
      return usage(argv[0]);
    expectfile = argv[4];
  }
  const SmokeCase *sc = findCase(casename);
  if (sc == (const SmokeCase *)0) {
    cerr << "unknown case: " << casename << endl;
    return usage(argv[0]);
  }

  AttributeId::initialize();
  ElementId::initialize();

  ostringstream out;
  try {
    runCase(sleighhome,*sc,out);
  } catch(LowlevelError &err) {
    cerr << "error: " << err.explain << endl;
    return 1;
  }
  string produced = out.str();
  cout << produced;
  cout.flush();

  if (expectfile.empty())
    return 0;

  ifstream in(expectfile.c_str());
  if (!in) {
    cerr << "cannot open expected file: " << expectfile << endl;
    return 1;
  }
  ostringstream expected;
  expected << in.rdbuf();
  if (expected.str() == produced) {
    cerr << casename << ": output matches " << expectfile << endl;
    return 0;
  }
  cerr << casename << ": output differs from " << expectfile << endl;
  istringstream a(produced);
  istringstream b(expected.str());
  string la,lb;
  int4 lineno = 0;
  while(true) {
    bool ha = static_cast<bool>(getline(a,la));
    bool hb = static_cast<bool>(getline(b,lb));
    lineno += 1;
    if (!ha && !hb) break;
    if (ha != hb || la != lb) {
      cerr << "line " << dec << lineno << ":" << endl;
      cerr << "  produced: " << (ha ? la : string("<end>")) << endl;
      cerr << "  expected: " << (hb ? lb : string("<end>")) << endl;
      break;
    }
  }
  return 1;
}
