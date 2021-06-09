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
#ifndef __CPUI_RULE_COMPILE__
#define __CPUI_RULE_COMPILE__

#include "unify.hh"

class RuleLexer {
  static int4 identlist[256];	// 1 is identifier, 2 is digit, 4=namechar
  map<string,int4> keywordmap;
  istream *s;
  char identifier[256];
  int4 identlength;
  int4 lookahead[4];
  int4 pos;
  bool endofstream;
  int4 lineno;
  int4 getNextChar(void) {
    char c;
    int4 ret = lookahead[pos];
    if (!endofstream) {
      (*s).get(c);
      if ((*s).eof()||(c=='\0')) {
	endofstream = true;
	lookahead[pos] = '\n';
      }
      else
	lookahead[pos] = c;
    }
    else
      lookahead[pos] = -1;
    pos = (pos+1)&3;
    return ret;
  }
  int4 next(int4 i) { return lookahead[(pos+i)&3]; }
  int4 scanIdentifier(void);
  int4 scanNumber(void);
  int4 buildString(int4 tokentype);
  int4 otherIdentifiers(void);
  void initKeywords(void);
public:
  RuleLexer(void);
  void initialize(istream &t);
  int4 getLineNo(void) { return lineno; }
  int4 nextToken(void);
};

class DummyTranslate : public Translate {
public:
  virtual void initialize(DocumentStorage &store) {}
  virtual const VarnodeData &getRegister(const string &nm) const { throw LowlevelError("Cannot add register to DummyTranslate"); }
  virtual string getRegisterName(AddrSpace *base,uintb off,int4 size) const { return ""; }
  virtual void getAllRegisters(map<VarnodeData,string> &reglist) const {}
  virtual void getUserOpNames(vector<string> &res) const {}
  virtual int4 instructionLength(const Address &baseaddr) const { return -1; }
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const { return -1; }
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const { return -1; }
};

class RuleCompile {
  ostream *error_stream;
  int4 errors;
  RuleLexer lexer;
  map<string,int4> namemap;
  ConstraintGroup *finalrule;
  vector<OpBehavior *> inst;
public:
  RuleCompile(void);
  ~RuleCompile(void);
  void ruleError(const char *s);
  int4 numErrors(void) const { return errors; }
  int4 getLineNo(void) { return lexer.getLineNo(); }
  void setFullRule(ConstraintGroup *full) { finalrule = full; }
  ConstraintGroup *getRule(void) { return finalrule; }
  ConstraintGroup *releaseRule(void) { ConstraintGroup *res = finalrule; finalrule = (ConstraintGroup *)0; return res; }
  const map<string,int4> &getNameMap(void) const { return namemap; }

  int4 findIdentifier(string *nm);

  ConstraintGroup *newOp(int4 id);
  ConstraintGroup *newVarnode(int4 id);
  ConstraintGroup *newConst(int4 id);

  ConstraintGroup *opCopy(ConstraintGroup *base,int4 opid);
  ConstraintGroup *opInput(ConstraintGroup *base,int8 *slot,int4 varid);
  ConstraintGroup *opInputAny(ConstraintGroup *base,int4 varid);
  ConstraintGroup *opInputConstVal(ConstraintGroup *base,int8 *slot,RHSConstant *rhs);
  ConstraintGroup *opOutput(ConstraintGroup *base,int4 varid);

  ConstraintGroup *varCopy(ConstraintGroup *base,int4 varid);
  ConstraintGroup *varConst(ConstraintGroup *base,RHSConstant *ex,RHSConstant *sz);
  ConstraintGroup *varDef(ConstraintGroup *base,int4 opid);
  ConstraintGroup *varDescend(ConstraintGroup *base,int4 opid);
  ConstraintGroup *varUniqueDescend(ConstraintGroup *base,int4 opid);

  ConstraintGroup *opCodeConstraint(ConstraintGroup *base,vector<OpCode> *oplist);
  ConstraintGroup *opCompareConstraint(ConstraintGroup *base,int4 opid,OpCode opc);
  ConstraintGroup *varCompareConstraint(ConstraintGroup *base,int4 varid,OpCode opc);
  ConstraintGroup *constCompareConstraint(ConstraintGroup *base,int4 constid,OpCode opc);
  ConstraintGroup *constNamedExpression(int4 id,RHSConstant *expr);

  ConstraintGroup *emptyGroup(void);
  ConstraintGroup *emptyOrGroup(void);
  ConstraintGroup *mergeGroups(ConstraintGroup *a,ConstraintGroup *b);
  ConstraintGroup *addOr(ConstraintGroup *base,ConstraintGroup *newor);
  ConstraintGroup *opCreation(int4 newid,OpCode oc,bool iafter,int4 oldid);
  ConstraintGroup *newUniqueOut(ConstraintGroup *base,int4 varid,int4 sz);
  ConstraintGroup *newSetInput(ConstraintGroup *base,RHSConstant *slot,int4 varid);
  ConstraintGroup *newSetInputConstVal(ConstraintGroup *base,RHSConstant *slot,RHSConstant *val,RHSConstant *sz);
  ConstraintGroup *removeInput(ConstraintGroup *base,RHSConstant *slot);
  ConstraintGroup *newSetOpcode(ConstraintGroup *base,OpCode opc);
  ConstraintGroup *booleanConstraint(bool ist,RHSConstant *expr);

  RHSConstant *constNamed(int4 id);
  RHSConstant *constAbsolute(int8 *val);
  RHSConstant *constBinaryExpression(RHSConstant *ex1,OpCode opc,RHSConstant *ex2);
  RHSConstant *constVarnodeSize(int4 varindex);
  RHSConstant *dotIdentifier(int4 id,string *str);

  int4 nextToken(void) { return lexer.nextToken(); }

  void setErrorStream(ostream &t) { error_stream = &t; }
  void run(istream &s,bool debug);
  void postProcess(void);
  int4 postProcessRule(vector<OpCode> &opcodelist);
  static ConstraintGroup *buildUnifyer(const string &rule,const vector<string> &idlist,vector<int4> &res);
};

class RuleGeneric : public Rule { // A user configurable rule, (a rule read in from a file)
  vector<OpCode> starterops;
  int4 opinit;			// Index of initialized op
  ConstraintGroup *constraint;
  UnifyState state;
public:
  RuleGeneric(const string &g,const string &nm,const vector<OpCode> &sops,int4 opi,ConstraintGroup *c);
  virtual ~RuleGeneric(void) { delete constraint; }
  virtual Rule *clone(const ActionGroupList &grouplist) const {
    if (!grouplist.contains(getGroup())) return (Rule *)0; return new RuleGeneric(getGroup(),getName(),starterops,opinit,(ConstraintGroup *)constraint->clone()); }
  virtual void getOpList(vector<uint4> &oplist) const;
  virtual int4 applyOp(PcodeOp *op,Funcdata &data);
  static RuleGeneric *build(const string &nm,const string &gp,const string &content);
};

/*
  Definition of the language

  Identifiers start with 'o' for named pcodeops
                         'v' for named varnodes
                         '#' for named constants

  A "statement" is a sequence of "steps", ending in a semicolon
  Steps are sequential, proceeding left to right.  Each step is either a 
  building step (which defines a new entity in terms of an existing entity), or a
  constraint (which forces a condition to be true)
  
  Building steps:

  o -> v                v is the output of o
  o1 -> o2              o2 is a (named) copy of o1
  o <- v                v is ANY input of o
  o <-(0) v             v is input 0 of o
  o <-(1) #c            input 1 to o is a constant (now named c)
  o <-(1) #0            input 1 to o is a constant with value 0
  
  v <- o                o is the defining op of v
  v -> o                o is ANY of the ops taking v as an input (may be inefficient)
  v ->! o               o is the one and only op taking v as input
  v1 -> v2              v2 is a (named) copy of v1

  Constraints:

  o(+)                  o must have an opcode equal '+'
  o1(== o2)             o1 and o2 must be the same pcode op
  o1(!= o2)             o1 and o2 must not be the same pcode op
  v1(== v2)             v1 and v2 must be the same varnode
  v1(!= v2)             v1 and v2 must not be the same varnode

  Statements can be grouped (into "statementlist") with parentheses '(' and ')'
  There is an OR operator

  '['   statementlist
      | statementlist 
      ...
  ']'

 */

#endif
