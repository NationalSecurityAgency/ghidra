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
#ifndef __SLGHPATTERN__
#define __SLGHPATTERN__

#include "context.hh"

// A mask/value pair viewed as two bitstreams
class PatternBlock {
  int4 offset;			// Offset to non-zero byte of mask
  int4 nonzerosize;		// Last byte(+1) containing nonzero mask
  vector<uintm> maskvec;	// Mask
  vector<uintm> valvec;		// Value
  void normalize(void);
public:
  PatternBlock(int4 off,uintm msk,uintm val);
  PatternBlock(bool tf);
  PatternBlock(const PatternBlock *a,const PatternBlock *b);
  PatternBlock(vector<PatternBlock *> &list);
  PatternBlock *commonSubPattern(const PatternBlock *b) const;
  PatternBlock *intersect(const PatternBlock *b) const;
  bool specializes(const PatternBlock *op2) const;
  bool identical(const PatternBlock *op2) const;
  PatternBlock *clone(void) const;
  void shift(int4 sa) { offset += sa; normalize(); }
  int4 getLength(void) const { return offset+nonzerosize; }
  uintm getMask(int4 startbit,int4 size) const;
  uintm getValue(int4 startbit,int4 size) const;
  bool alwaysTrue(void) const { return (nonzerosize==0); }
  bool alwaysFalse(void) const { return (nonzerosize==-1); }
  bool isInstructionMatch(ParserWalker &walker) const;
  bool isContextMatch(ParserWalker &walker) const;
  void saveXml(ostream &s) const;
  void restoreXml(const Element *el);
};

class DisjointPattern;
class Pattern {
public:
  virtual ~Pattern(void) {}
  virtual Pattern *simplifyClone(void) const=0;
  virtual void shiftInstruction(int4 sa)=0;
  virtual Pattern *doOr(const Pattern *b,int4 sa) const=0;
  virtual Pattern *doAnd(const Pattern *b,int4 sa) const=0;
  virtual Pattern *commonSubPattern(const Pattern *b,int4 sa) const=0;
  virtual bool isMatch(ParserWalker &walker) const=0; // Does this pattern match context
  virtual int4 numDisjoint(void) const=0;
  virtual DisjointPattern *getDisjoint(int4 i) const=0;
  virtual bool alwaysTrue(void) const=0;
  virtual bool alwaysFalse(void) const=0;
  virtual bool alwaysInstructionTrue(void) const=0;
  virtual void saveXml(ostream &s) const=0;
  virtual void restoreXml(const Element *el)=0;
};

class DisjointPattern : public Pattern { // A pattern with no ORs in it
  virtual PatternBlock *getBlock(bool context) const=0;
public:
  virtual int4 numDisjoint(void) const { return 0; }
  virtual DisjointPattern *getDisjoint(int4 i) const { return (DisjointPattern *)0; }
  uintm getMask(int4 startbit,int4 size,bool context) const;
  uintm getValue(int4 startbit,int4 size,bool context) const;
  int4 getLength(bool context) const;
  bool specializes(const DisjointPattern *op2) const;
  bool identical(const DisjointPattern *op2) const;
  bool resolvesIntersect(const DisjointPattern *op1,const DisjointPattern *op2) const;
  static DisjointPattern *restoreDisjoint(const Element *el);
};

class InstructionPattern : public DisjointPattern { // Matches the instruction bitstream
  PatternBlock *maskvalue;
  virtual PatternBlock *getBlock(bool context) const { return context ? (PatternBlock *)0 : maskvalue; }
public:
  InstructionPattern(void) { maskvalue = (PatternBlock *)0; } // For use with restoreXml
  InstructionPattern(PatternBlock *mv) { maskvalue = mv; }
  InstructionPattern(bool tf) { maskvalue = new PatternBlock(tf); }
  PatternBlock *getBlock(void) { return maskvalue; }
  virtual ~InstructionPattern(void) { if (maskvalue != (PatternBlock *)0) delete maskvalue; }
  virtual Pattern *simplifyClone(void) const { return new InstructionPattern(maskvalue->clone()); }
  virtual void shiftInstruction(int4 sa) { maskvalue->shift(sa); }
  virtual Pattern *doOr(const Pattern *b,int4 sa) const;
  virtual Pattern *doAnd(const Pattern *b,int4 sa) const;
  virtual Pattern *commonSubPattern(const Pattern *b,int4 sa) const;
  virtual bool isMatch(ParserWalker &walker) const { return maskvalue->isInstructionMatch(walker); }
  virtual bool alwaysTrue(void) const { return maskvalue->alwaysTrue(); }
  virtual bool alwaysFalse(void) const { return maskvalue->alwaysFalse(); }
  virtual bool alwaysInstructionTrue(void) const { return maskvalue->alwaysTrue(); }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
};

class ContextPattern : public DisjointPattern { // Matches the context bitstream
  PatternBlock *maskvalue;
  virtual PatternBlock *getBlock(bool context) const { return context ? maskvalue : (PatternBlock *)0; }
public:
  ContextPattern(void) { maskvalue = (PatternBlock *)0; } // For use with restoreXml
  ContextPattern(PatternBlock *mv) { maskvalue = mv; }
  PatternBlock *getBlock(void) { return maskvalue; }
  virtual ~ContextPattern(void) { if (maskvalue != (PatternBlock *)0) delete maskvalue; }
  virtual Pattern *simplifyClone(void) const { return new ContextPattern(maskvalue->clone()); }
  virtual void shiftInstruction(int4 sa) { }  // do nothing
  virtual Pattern *doOr(const Pattern *b,int4 sa) const;
  virtual Pattern *doAnd(const Pattern *b,int4 sa) const;
  virtual Pattern *commonSubPattern(const Pattern *b,int4 sa) const;
  virtual bool isMatch(ParserWalker &walker) const { return maskvalue->isContextMatch(walker); }
  virtual bool alwaysTrue(void) const { return maskvalue->alwaysTrue(); }
  virtual bool alwaysFalse(void) const { return maskvalue->alwaysFalse(); }
  virtual bool alwaysInstructionTrue(void) const { return true; }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
};

// A pattern with a context piece and an instruction piece
class CombinePattern : public DisjointPattern {
  ContextPattern *context;	// Context piece
  InstructionPattern *instr;	// Instruction piece
  virtual PatternBlock *getBlock(bool cont) const { return cont ? context->getBlock() : instr->getBlock(); }
public:
  CombinePattern(void) { context = (ContextPattern *)0; instr = (InstructionPattern *)0; }
  CombinePattern(ContextPattern *con,InstructionPattern *in) {
    context = con; instr = in; }
  virtual ~CombinePattern(void);
  virtual Pattern *simplifyClone(void) const;
  virtual void shiftInstruction(int4 sa) { instr->shiftInstruction(sa); }
  virtual bool isMatch(ParserWalker &walker) const;
  virtual bool alwaysTrue(void) const;
  virtual bool alwaysFalse(void) const;
  virtual bool alwaysInstructionTrue(void) const { return instr->alwaysInstructionTrue(); }
  virtual Pattern *doOr(const Pattern *b,int4 sa) const;
  virtual Pattern *doAnd(const Pattern *b,int4 sa) const;
  virtual Pattern *commonSubPattern(const Pattern *b,int4 sa) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
};

class OrPattern : public Pattern {
  vector<DisjointPattern *> orlist;
public:
  OrPattern(void) {}		// For use with restoreXml
  OrPattern(DisjointPattern *a,DisjointPattern *b);
  OrPattern(const vector<DisjointPattern *> &list);
  virtual ~OrPattern(void);
  virtual Pattern *simplifyClone(void) const;
  virtual void shiftInstruction(int4 sa);
  virtual bool isMatch(ParserWalker &walker) const;
  virtual int4 numDisjoint(void) const { return orlist.size(); }
  virtual DisjointPattern *getDisjoint(int4 i) const { return orlist[i]; }
  virtual bool alwaysTrue(void) const;
  virtual bool alwaysFalse(void) const;
  virtual bool alwaysInstructionTrue(void) const;
  virtual Pattern *doOr(const Pattern *b,int4 sa) const;
  virtual Pattern *doAnd(const Pattern *b,int4 sa) const;
  virtual Pattern *commonSubPattern(const Pattern *b,int4 sa) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el);
};

#endif
