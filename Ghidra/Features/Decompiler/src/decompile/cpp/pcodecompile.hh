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
#ifndef __PCODE_COMPILE__
#define __PCODE_COMPILE__

#include "slghsymbol.hh"

class Location {
  string filename;
  int4 lineno;
public:
  Location(void) {}
  Location(const string &fname, const int4 line) { filename = fname; lineno = line; }
  string getFilename(void) const { return filename; }
  int4 getLineno(void) const { return lineno; }
  string format(void) const;
};

struct StarQuality {
  ConstTpl id;
  uint4 size;
};

class ExprTree {		// A flattened expression tree
  friend class PcodeCompile;
  vector<OpTpl *> *ops;	// flattened ops making up the expression
  VarnodeTpl *outvn;		// Output varnode of the expression
				// If the last op has an output, -outvn- is
				// a COPY of that varnode
public:
  ExprTree(void) { ops = (vector<OpTpl *> *)0; outvn = (VarnodeTpl *)0; }
  ExprTree(VarnodeTpl *vn);
  ExprTree(OpTpl *op);
  ~ExprTree(void);
  void setOutput(VarnodeTpl *newout);
  VarnodeTpl *getOut(void) { return outvn; }
  const ConstTpl &getSize(void) const { return outvn->getSize(); }
  static vector<OpTpl *> *appendParams(OpTpl *op,vector<ExprTree *> *param);
  static vector<OpTpl *> *toVector(ExprTree *expr);
};

class PcodeCompile {
  AddrSpace *defaultspace;
  AddrSpace *constantspace;
  AddrSpace *uniqspace;
  uint4 local_labelcount;	// Number of labels in current constructor
  bool enforceLocalKey;		// Force slaspec to use 'local' keyword when defining temporary varnodes
  virtual uintb allocateTemp(void)=0;
  virtual void addSymbol(SleighSymbol *sym)=0;
public:
  PcodeCompile(void) { defaultspace=(AddrSpace *)0; constantspace=(AddrSpace *)0;
  	  	  	  	  	  uniqspace=(AddrSpace *)0; local_labelcount=0; enforceLocalKey=false; }
  virtual ~PcodeCompile(void) {}
  virtual const Location *getLocation(SleighSymbol *sym) const=0;
  virtual void reportError(const Location *loc, const string &msg)=0;
  virtual void reportWarning(const Location *loc, const string &msg)=0;
  void resetLabelCount(void) { local_labelcount=0; }
  void setDefaultSpace(AddrSpace *spc) { defaultspace = spc; }
  void setConstantSpace(AddrSpace *spc) { constantspace = spc; }
  void setUniqueSpace(AddrSpace *spc) { uniqspace = spc; }
  void setEnforceLocalKey(bool val) { enforceLocalKey = val; }
  AddrSpace *getDefaultSpace(void) const { return defaultspace; }
  AddrSpace *getConstantSpace(void) const { return constantspace; }
  VarnodeTpl *buildTemporary(void);
  LabelSymbol *defineLabel(string *name);
  vector<OpTpl *> *placeLabel(LabelSymbol *sym);
  vector<OpTpl *> *newOutput(bool usesLocalKey,ExprTree *rhs,string *varname,uint4 size=0);
  void newLocalDefinition(string *varname,uint4 size=0);
  ExprTree *createOp(OpCode opc,ExprTree *vn);
  ExprTree *createOp(OpCode opc,ExprTree *vn1,ExprTree *vn2);
  ExprTree *createOpOut(VarnodeTpl *outvn,OpCode opc,ExprTree *vn1,ExprTree *vn2);
  ExprTree *createOpOutUnary(VarnodeTpl *outvn,OpCode opc,ExprTree *vn);
  vector<OpTpl *> *createOpNoOut(OpCode opc,ExprTree *vn);
  vector<OpTpl *> *createOpNoOut(OpCode opc,ExprTree *vn1,ExprTree *vn2);
  vector<OpTpl *> *createOpConst(OpCode opc,uintb val);
  ExprTree *createLoad(StarQuality *qual,ExprTree *ptr);
  vector<OpTpl *> *createStore(StarQuality *qual,ExprTree *ptr,ExprTree *val);
  ExprTree *createUserOp(UserOpSymbol *sym,vector<ExprTree *> *param);
  vector<OpTpl *> *createUserOpNoOut(UserOpSymbol *sym,vector<ExprTree *> *param);
  ExprTree *createVariadic(OpCode opc,vector<ExprTree *> *param);
  void appendOp(OpCode opc,ExprTree *res,uintb constval,int4 constsz);
  VarnodeTpl *buildTruncatedVarnode(VarnodeTpl *basevn,uint4 bitoffset,uint4 numbits);
  vector<OpTpl *> *assignBitRange(VarnodeTpl *vn,uint4 bitoffset,uint4 numbits,ExprTree *rhs);
  ExprTree *createBitRange(SpecificSymbol *sym,uint4 bitoffset,uint4 numbits);
  VarnodeTpl *addressOf(VarnodeTpl *var,uint4 size);
  static void force_size(VarnodeTpl *vt,const ConstTpl &size,const vector<OpTpl *> &ops);
  static void matchSize(int4 j,OpTpl *op,bool inputonly,const vector<OpTpl *> &ops);
  static void fillinZero(OpTpl *op,const vector<OpTpl *> &ops);
  static bool propagateSize(ConstructTpl *ct);
};

#endif
