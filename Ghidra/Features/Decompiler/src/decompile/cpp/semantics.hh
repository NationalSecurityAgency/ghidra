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
#ifndef __SEMANTICS__
#define __SEMANTICS__

#include "context.hh"

// We remap these opcodes for internal use during pcode generation

#define BUILD CPUI_MULTIEQUAL
#define DELAY_SLOT CPUI_INDIRECT
#define CROSSBUILD CPUI_PTRSUB
#define MACROBUILD CPUI_CAST
#define LABELBUILD CPUI_PTRADD

class Translate;		// Forward declaration
class HandleTpl;		// Forward declaration
class ConstTpl {
public:
  enum const_type { real=0, handle=1, j_start=2, j_next=3, j_curspace=4, 
		    j_curspace_size=5, spaceid=6, j_relative=7,
		    j_flowref=8, j_flowref_size=9, j_flowdest=10, j_flowdest_size=11 };
  enum v_field { v_space=0, v_offset=1, v_size=2, v_offset_plus=3 };
private:
  const_type type;
  union {
    //    uintb real;			// an actual constant
    AddrSpace *spaceid;	// Id (pointer) for registered space
    int4 handle_index;		// Place holder for run-time determined value
  } value;
  uintb value_real;
  v_field select;		// Which part of handle to use as constant
  static void printHandleSelector(ostream &s,v_field val);
  static v_field readHandleSelector(const string &name);
public:
  ConstTpl(void) { type = real; value_real = 0; }
  ConstTpl(const ConstTpl &op2) {
    type=op2.type; value=op2.value; value_real=op2.value_real; select=op2.select; }
  ConstTpl(const_type tp,uintb val);
  ConstTpl(const_type tp);
  ConstTpl(AddrSpace *sid);
  ConstTpl(const_type tp,int4 ht,v_field vf);
  ConstTpl(const_type tp,int4 ht,v_field vf,uintb plus);
  bool isConstSpace(void) const;
  bool isUniqueSpace(void) const;
  bool operator==(const ConstTpl &op2) const;
  bool operator<(const ConstTpl &op2) const;
  uintb getReal(void) const { return value_real; }
  AddrSpace *getSpace(void) const { return value.spaceid; }
  int4 getHandleIndex(void) const { return value.handle_index; }
  const_type getType(void) const { return type; }
  v_field getSelect(void) const { return select; }
  uintb fix(const ParserWalker &walker) const;
  AddrSpace *fixSpace(const ParserWalker &walker) const;
  void transfer(const vector<HandleTpl *> &params);
  bool isZero(void) const { return ((type==real)&&(value_real==0)); }
  void changeHandleIndex(const vector<int4> &handmap);
  void fillinSpace(FixedHandle &hand,const ParserWalker &walker) const;
  void fillinOffset(FixedHandle &hand,const ParserWalker &walker) const;
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,const AddrSpaceManager *manage);
};

class VarnodeTpl {
  friend class OpTpl;
  friend class HandleTpl;
  ConstTpl space,offset,size;
  bool unnamed_flag;
public:
  VarnodeTpl(int4 hand,bool zerosize);
  VarnodeTpl(void) : space(), offset(), size() { unnamed_flag=false; }
  VarnodeTpl(const ConstTpl &sp,const ConstTpl &off,const ConstTpl &sz);
  VarnodeTpl(const VarnodeTpl &vn);
  const ConstTpl &getSpace(void) const { return space; }
  const ConstTpl &getOffset(void) const { return offset; }
  const ConstTpl &getSize(void) const { return size; }
  bool isDynamic(const ParserWalker &walker) const;
  int4 transfer(const vector<HandleTpl *> &params);
  bool isZeroSize(void) const { return size.isZero(); }
  bool operator<(const VarnodeTpl &op2) const;
  void setOffset(uintb constVal) { offset = ConstTpl(ConstTpl::real,constVal); }
  void setRelative(uintb constVal) { offset = ConstTpl(ConstTpl::j_relative,constVal); }
  void setSize(const ConstTpl &sz ) { size = sz; }
  bool isUnnamed(void) const { return unnamed_flag; }
  void setUnnamed(bool val) { unnamed_flag = val; }
  bool isLocalTemp(void) const;
  bool isRelative(void) const { return (offset.getType() == ConstTpl::j_relative); }
  void changeHandleIndex(const vector<int4> &handmap);
  bool adjustTruncation(int4 sz,bool isbigendian);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,const AddrSpaceManager *manage);
};

class HandleTpl {
  ConstTpl space;
  ConstTpl size;
  ConstTpl ptrspace;
  ConstTpl ptroffset;
  ConstTpl ptrsize;
  ConstTpl temp_space;
  ConstTpl temp_offset;
public:
  HandleTpl(void) {}
  HandleTpl(const VarnodeTpl *vn);
  HandleTpl(const ConstTpl &spc,const ConstTpl &sz,const VarnodeTpl *vn,
	     AddrSpace *t_space,uintb t_offset);
  const ConstTpl &getSpace(void) const { return space; }
  const ConstTpl &getPtrSpace(void) const { return ptrspace; }
  const ConstTpl &getPtrOffset(void) const { return ptroffset; }
  const ConstTpl &getPtrSize(void) const { return ptrsize; }
  const ConstTpl &getSize(void) const { return size; }
  const ConstTpl &getTempSpace(void) const { return temp_space; }
  const ConstTpl &getTempOffset(void) const { return temp_offset; }
  void setSize(const ConstTpl &sz) { size = sz; }
  void setPtrSize(const ConstTpl &sz) { ptrsize=sz; }
  void setPtrOffset(uintb val) { ptroffset = ConstTpl(ConstTpl::real,val); }
  void setTempOffset(uintb val) { temp_offset = ConstTpl(ConstTpl::real,val); }
  void fix(FixedHandle &hand,const ParserWalker &walker) const;
  void changeHandleIndex(const vector<int4> &handmap);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,const AddrSpaceManager *manage);
};

class OpTpl {
  VarnodeTpl *output;
  OpCode opc;
  vector<VarnodeTpl *> input;
public:
  OpTpl(void) {}
  OpTpl(OpCode oc) { opc = oc; output = (VarnodeTpl *)0; }
  ~OpTpl(void);
  VarnodeTpl *getOut(void) const { return output; }
  int4 numInput(void) const { return input.size(); }
  VarnodeTpl *getIn(int4 i) const { return input[i]; }
  OpCode getOpcode(void) const { return opc; }
  bool isZeroSize(void) const;
  void setOpcode(OpCode o) { opc = o; }
  void setOutput(VarnodeTpl *vt) { output = vt; }
  void clearOutput(void) { delete output; output = (VarnodeTpl *)0; }
  void addInput(VarnodeTpl *vt) { input.push_back(vt); }
  void setInput(VarnodeTpl *vt,int4 slot) { input[slot] = vt; }
  void removeInput(int4 index);
  void changeHandleIndex(const vector<int4> &handmap);
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el,const AddrSpaceManager *manage);
};

class ConstructTpl {
  friend class SleighCompile;
protected:
  uint4 delayslot;
  uint4 numlabels;		// Number of label templates
  vector<OpTpl *> vec;
  HandleTpl *result;
  void setOpvec(vector<OpTpl *> &opvec) { vec = opvec; }
  void setNumLabels(uint4 val) { numlabels = val; }
public:
  ConstructTpl(void) { delayslot=0; numlabels=0; result = (HandleTpl *)0; }
  ~ConstructTpl(void);
  uint4 delaySlot(void) const { return delayslot; }
  uint4 numLabels(void) const { return numlabels; }
  const vector<OpTpl *> &getOpvec(void) const { return vec; }
  HandleTpl *getResult(void) const { return result; }
  bool addOp(OpTpl *ot);
  bool addOpList(const vector<OpTpl *> &oplist);
  void setResult(HandleTpl *t) { result = t; }
  int4 fillinBuild(vector<int4> &check,AddrSpace *const_space);
  bool buildOnly(void) const;
  void changeHandleIndex(const vector<int4> &handmap);
  void setInput(VarnodeTpl *vn,int4 index,int4 slot);
  void setOutput(VarnodeTpl *vn,int4 index);
  void deleteOps(const vector<int4> &indices);
  void saveXml(ostream &s,int4 sectionid) const;
  int4 restoreXml(const Element *el,const AddrSpaceManager *manage);
};

class PcodeEmit;   // Forward declaration for emitter

class PcodeBuilder { // SLEIGH specific pcode generator
  uint4 labelbase;
  uint4 labelcount;
protected:
  ParserWalker *walker;
  virtual void dump( OpTpl *op )=0;
public:
  PcodeBuilder(uint4 lbcnt) { labelbase=labelcount=lbcnt; }
  virtual ~PcodeBuilder(void) {}

  uint4 getLabelBase(void) const { return labelbase; }
  ParserWalker *getCurrentWalker() const { return walker; }
  void build(ConstructTpl *construct,int4 secnum);
  virtual void appendBuild(OpTpl *bld,int4 secnum)=0;
  virtual void delaySlot(OpTpl *op)=0;
  virtual void setLabel(OpTpl *op)=0;
  virtual void appendCrossBuild(OpTpl *bld,int4 secnum)=0;
};

#endif
