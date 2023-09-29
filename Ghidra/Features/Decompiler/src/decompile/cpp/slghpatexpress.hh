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
#ifndef __SLGHPATEXPRESS_HH__
#define __SLGHPATEXPRESS_HH__

#include "slghpattern.hh"

namespace ghidra {

class TokenPattern {
  Pattern *pattern;
  vector<Token *> toklist;
  bool leftellipsis;
  bool rightellipsis;
  static PatternBlock *buildSingle(int4 startbit,int4 endbit,uintm byteval);
  static PatternBlock *buildBigBlock(int4 size,int4 bitstart,int4 bitend,intb value);
  static PatternBlock *buildLittleBlock(int4 size,int4 bitstart,int4 bitend,intb value);
  int4 resolveTokens(const TokenPattern &tokpat1,const TokenPattern &tokpat2);
  TokenPattern(Pattern *pat) { pattern = pat; leftellipsis=false; rightellipsis=false; }
public:
  TokenPattern(void);		// TRUE pattern unassociated with a token
  TokenPattern(bool tf);	// TRUE or FALSE pattern unassociated with a token
  TokenPattern(Token *tok);	// TRUE pattern associated with token -tok-
  TokenPattern(Token *tok,intb value,int4 bitstart,int4 bitend);
  TokenPattern(intb value,int4 startbit,int4 endbit);
  TokenPattern(const TokenPattern &tokpat);
  ~TokenPattern(void) { delete pattern; }
  const TokenPattern &operator=(const TokenPattern &tokpat);
  void setLeftEllipsis(bool val) { leftellipsis = val; }
  void setRightEllipsis(bool val) { rightellipsis = val; }
  bool getLeftEllipsis(void) const { return leftellipsis; }
  bool getRightEllipsis(void) const { return rightellipsis; }
  TokenPattern doAnd(const TokenPattern &tokpat) const;
  TokenPattern doOr(const TokenPattern &tokpat) const;
  TokenPattern doCat(const TokenPattern &tokpat) const;
  TokenPattern commonSubPattern(const TokenPattern &tokpat) const;
  Pattern *getPattern(void) const { return pattern; }
  int4 getMinimumLength(void) const;
  bool alwaysTrue(void) const { return pattern->alwaysTrue(); }
  bool alwaysFalse(void) const { return pattern->alwaysFalse(); }
  bool alwaysInstructionTrue(void) const { return pattern->alwaysInstructionTrue(); }
};

class PatternValue;
class PatternExpression {
  int4 refcount;			// Number of objects referencing this
				// for deletion
protected:
  virtual ~PatternExpression(void) {} // Only delete through release
public:
  PatternExpression(void) { refcount = 0; }
  virtual intb getValue(ParserWalker &walker) const=0;
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const=0;
  virtual void listValues(vector<const PatternValue *> &list) const=0;
  virtual void getMinMax(vector<intb> &minlist,vector<intb> &maxlist) const=0;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const=0;
  virtual void saveXml(ostream &s) const=0;
  virtual void restoreXml(const Element *el,Translate *trans)=0;
  intb getSubValue(const vector<intb> &replace) {
    int4 listpos = 0;
    return getSubValue(replace,listpos); }
  void layClaim(void) { refcount += 1; }
  static void release(PatternExpression *p);
  static PatternExpression *restoreExpression(const Element *el,Translate *trans);
};

class PatternValue : public PatternExpression {
public:
  virtual TokenPattern genPattern(intb val) const=0;
  virtual void listValues(vector<const PatternValue *> &list) const { list.push_back(this); }
  virtual void getMinMax(vector<intb> &minlist,vector<intb> &maxlist) const { 
    minlist.push_back(minValue()); maxlist.push_back(maxValue()); }
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const { return replace[listpos++]; }
  virtual intb minValue(void) const=0;
  virtual intb maxValue(void) const=0;
};

class TokenField : public PatternValue {
  Token *tok;
  bool bigendian;
  bool signbit;
  int4 bitstart,bitend;		// Bits within the token, 0 bit is LEAST significant
  int4 bytestart,byteend;	// Bytes to read to get value
  int4 shift;			// Amount to shift to align value  (bitstart % 8)
public:
  TokenField(void) {}		// For use with restoreXml
  TokenField(Token *tk,bool s,int4 bstart,int4 bend);
  virtual intb getValue(ParserWalker &walker) const;
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(tok); }
  virtual TokenPattern genPattern(intb val) const;
  virtual intb minValue(void) const { return 0; }
  virtual intb maxValue(void) const { intb res=0; return zero_extend(~res,bitend-bitstart); }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};

class ContextField : public PatternValue {
  int4 startbit,endbit;
  int4 startbyte,endbyte;
  int4 shift;
  bool signbit;
public:
  ContextField(void) {}		// For use with restoreXml
  ContextField(bool s,int4 sbit,int4 ebit);
  int4 getStartBit(void) const { return startbit; }
  int4 getEndBit(void) const { return endbit; }
  bool getSignBit(void) const { return signbit; }
  virtual intb getValue(ParserWalker &walker) const;
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual TokenPattern genPattern(intb val) const;
  virtual intb minValue(void) const { return 0; }
  virtual intb maxValue(void) const { intb res=0; return zero_extend(~res,(endbit-startbit)); }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};

class ConstantValue : public PatternValue {
  intb val;
public:
  ConstantValue(void) {}	// For use with restoreXml
  ConstantValue(intb v) { val = v; }
  virtual intb getValue(ParserWalker &walker) const { return val; }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual TokenPattern genPattern(intb v) const { return TokenPattern(val==v); }
  virtual intb minValue(void) const { return val; }
  virtual intb maxValue(void) const { return val; }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};

class StartInstructionValue : public PatternValue {
public:
  StartInstructionValue(void) {}
  virtual intb getValue(ParserWalker &walker) const {
    return (intb)AddrSpace::byteToAddress(walker.getAddr().getOffset(),walker.getAddr().getSpace()->getWordSize()); }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual TokenPattern genPattern(intb val) const { return TokenPattern(); }
  virtual intb minValue(void) const { return (intb)0; }
  virtual intb maxValue(void) const { return (intb)0; }
  virtual void saveXml(ostream &s) const { s << "<start_exp/>"; }
  virtual void restoreXml(const Element *el,Translate *trans) {}
};
                                                                                        
class EndInstructionValue : public PatternValue {
public:
  EndInstructionValue(void) {}
  virtual intb getValue(ParserWalker &walker) const {
    return (intb)AddrSpace::byteToAddress(walker.getNaddr().getOffset(),walker.getNaddr().getSpace()->getWordSize()); }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual TokenPattern genPattern(intb val) const { return TokenPattern(); }
  virtual intb minValue(void) const { return (intb)0; }
  virtual intb maxValue(void) const { return (intb)0; }
  virtual void saveXml(ostream &s) const { s << "<end_exp/>"; }
  virtual void restoreXml(const Element *el,Translate *trans) {}
};

class Next2InstructionValue : public PatternValue {
public:
  Next2InstructionValue(void) {}
  virtual intb getValue(ParserWalker &walker) const {
    return (intb)AddrSpace::byteToAddress(walker.getN2addr().getOffset(),walker.getN2addr().getSpace()->getWordSize()); }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual TokenPattern genPattern(intb val) const { return TokenPattern(); }
  virtual intb minValue(void) const { return (intb)0; }
  virtual intb maxValue(void) const { return (intb)0; }
  virtual void saveXml(ostream &s) const { s << "<next2_exp/>"; }
  virtual void restoreXml(const Element *el,Translate *trans) {}
};

class Constructor;		// Forward declaration
class OperandSymbol;
class OperandValue : public PatternValue {
  int4 index;			// This is the defining field of expression
  Constructor *ct;		// cached pointer to constructor
public:
  OperandValue(void) { } // For use with restoreXml
  OperandValue(int4 ind,Constructor *c) { index = ind; ct = c; }
  void changeIndex(int4 newind) { index = newind; }
  bool isConstructorRelative(void) const;
  const string &getName(void) const;
  virtual TokenPattern genPattern(intb val) const;
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return ops[index]; }
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual intb minValue(void) const;
  virtual intb maxValue(void) const;
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};

class BinaryExpression : public PatternExpression {
  PatternExpression *left,*right;
protected:
  virtual ~BinaryExpression(void);
public:
  BinaryExpression(void) { left = (PatternExpression *)0; right = (PatternExpression *)0; } // For use with restoreXml
  BinaryExpression(PatternExpression *l,PatternExpression *r);
  PatternExpression *getLeft(void) const { return left; }
  PatternExpression *getRight(void) const { return right; }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual void listValues(vector<const PatternValue *> &list) const {
    left->listValues(list); right->listValues(list); }
  virtual void getMinMax(vector<intb> &minlist,vector<intb> &maxlist) const {
    left->getMinMax(minlist,maxlist); right->getMinMax(minlist,maxlist); }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};

class UnaryExpression : public PatternExpression {
  PatternExpression *unary;
protected:
  virtual ~UnaryExpression(void);
public:
  UnaryExpression(void) { unary = (PatternExpression *)0; } // For use with restoreXml
  UnaryExpression(PatternExpression *u);
  PatternExpression *getUnary(void) const { return unary; }
  virtual TokenPattern genMinPattern(const vector<TokenPattern> &ops) const { return TokenPattern(); }
  virtual void listValues(vector<const PatternValue *> &list) const {
    unary->listValues(list); }
  virtual void getMinMax(vector<intb> &minlist,vector<intb> &maxlist) const {
    unary->getMinMax(minlist,maxlist);
  }
  virtual void saveXml(ostream &s) const;
  virtual void restoreXml(const Element *el,Translate *trans);
};  

class PlusExpression : public BinaryExpression {
public:
  PlusExpression(void) {}	// For use by restoreXml
  PlusExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};
  
class SubExpression : public BinaryExpression {
public:
  SubExpression(void) {}	// For use with restoreXml
  SubExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};
  
class MultExpression : public BinaryExpression {
public:
  MultExpression(void) {}	// For use with restoreXml
  MultExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};
  
class LeftShiftExpression : public BinaryExpression {
public:
  LeftShiftExpression(void) {}
  LeftShiftExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};

class RightShiftExpression : public BinaryExpression {
public:
  RightShiftExpression(void) {}
  RightShiftExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};

class AndExpression : public BinaryExpression {
public:
  AndExpression(void) {}
  AndExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};
  
class OrExpression : public BinaryExpression {
public:
  OrExpression(void) {}
  OrExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};
  
class XorExpression : public BinaryExpression {
public:
  XorExpression(void) {}
  XorExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};

class DivExpression : public BinaryExpression {
public:
  DivExpression(void) {}
  DivExpression(PatternExpression *l,PatternExpression *r) : BinaryExpression(l,r) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};

class MinusExpression : public UnaryExpression {
public:
  MinusExpression(void) {}
  MinusExpression(PatternExpression *u) : UnaryExpression(u) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};  

class NotExpression : public UnaryExpression {
public:
  NotExpression(void) {}
  NotExpression(PatternExpression *u) : UnaryExpression(u) {}
  virtual intb getValue(ParserWalker &walker) const;
  virtual intb getSubValue(const vector<intb> &replace,int4 &listpos) const;
  virtual void saveXml(ostream &s) const;
};  

struct OperandResolve {
  vector<OperandSymbol *> &operands;
  OperandResolve(vector<OperandSymbol *> &ops) : operands(ops) {
    base=-1; offset=0; cur_rightmost = -1; size = 0; }
  int4 base;		// Current base operand (as we traverse the pattern equation from left to right)
  int4 offset;		// Bytes we have traversed from the LEFT edge of the current base
  int4 cur_rightmost;	// (resulting) rightmost operand in our pattern
  int4 size;		// (resulting) bytes traversed from the LEFT edge of the rightmost
};

// operandOrder returns a vector of the self-defining OperandSymbols as the appear
// in left to right order in the pattern
class PatternEquation {
  int4 refcount;			// Number of objects referencing this
protected:
  mutable TokenPattern resultpattern; // Resulting pattern generated by this equation
  virtual ~PatternEquation(void) {} // Only delete through release
public:
  PatternEquation(void) { refcount = 0; }
  const TokenPattern &getTokenPattern(void) const { return resultpattern; }
  virtual void genPattern(const vector<TokenPattern> &ops) const=0;
  virtual bool resolveOperandLeft(OperandResolve &state) const=0;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const {}
  void layClaim(void) { refcount += 1; }
  static void release(PatternEquation *pateq);
};

class OperandEquation : public PatternEquation { // Equation that defines operand
  int4 index;
public:
  OperandEquation(int4 ind) { index = ind; }
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

class UnconstrainedEquation : public PatternEquation { // Unconstrained equation, just get tokens
  PatternExpression *patex;
protected:
  virtual ~UnconstrainedEquation(void);
public:
  UnconstrainedEquation(PatternExpression *p);
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
};

class ValExpressEquation : public PatternEquation {
protected:
  PatternValue *lhs;
  PatternExpression *rhs;
  virtual ~ValExpressEquation(void);
public:
  ValExpressEquation(PatternValue *l,PatternExpression *r);
  virtual bool resolveOperandLeft(OperandResolve &state) const;
};

class EqualEquation : public ValExpressEquation {
public:
  EqualEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class NotEqualEquation : public ValExpressEquation {
public:
  NotEqualEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class LessEquation : public ValExpressEquation {
public:
  LessEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class LessEqualEquation : public ValExpressEquation {
public:
  LessEqualEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class GreaterEquation : public ValExpressEquation {
public:
  GreaterEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class GreaterEqualEquation : public ValExpressEquation {
public:
  GreaterEqualEquation(PatternValue *l,PatternExpression *r) : ValExpressEquation(l,r) {}
  virtual void genPattern(const vector<TokenPattern> &ops) const;
};

class EquationAnd : public PatternEquation { // Pattern Equations ANDed together
  PatternEquation *left;
  PatternEquation *right;
protected:
  virtual ~EquationAnd(void);
public:
  EquationAnd(PatternEquation *l,PatternEquation *r);
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

class EquationOr : public PatternEquation { // Pattern Equations ORed together
  PatternEquation *left;
  PatternEquation *right;
protected:
  virtual ~EquationOr(void);
public:
  EquationOr(PatternEquation *l,PatternEquation *r);
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

class EquationCat : public PatternEquation { // Pattern Equations concatenated
  PatternEquation *left;
  PatternEquation *right;
protected:
  virtual ~EquationCat(void);
public:
  EquationCat(PatternEquation *l,PatternEquation *r);
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

class EquationLeftEllipsis : public PatternEquation { // Equation preceded by ellipses
  PatternEquation *eq;
protected:
  virtual ~EquationLeftEllipsis(void) { PatternEquation::release(eq); }
public:
  EquationLeftEllipsis(PatternEquation *e) { (eq=e)->layClaim(); }
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

class EquationRightEllipsis : public PatternEquation { // Equation preceded by ellipses
  PatternEquation *eq;
protected:
  virtual ~EquationRightEllipsis(void) { PatternEquation::release(eq); }
public:
  EquationRightEllipsis(PatternEquation *e) { (eq=e)->layClaim(); }
  virtual void genPattern(const vector<TokenPattern> &ops) const;
  virtual bool resolveOperandLeft(OperandResolve &state) const;
  virtual void operandOrder(Constructor *ct,vector<OperandSymbol *> &order) const;
};

} // End namespace ghidra
#endif
