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
#ifdef CPUI_RULECOMPILE
#include "rulecompile.hh"
#include "ruleparse.hh"

RuleCompile *rulecompile;
extern int4 ruleparsedebug;
extern int4 ruleparseparse(void);

class MyLoadImage : public LoadImage { // Dummy loadimage
public:
  MyLoadImage(void) : LoadImage("nofile") {}
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr) { for(int4 i=0;i<size;++i) ptr[i] = 0; }
  virtual string getArchType(void) const { return "myload"; }
  virtual void adjustVma(long adjust) { }
};

int4 RuleLexer::identlist[256] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 0, 0, 0, 0, 0,
  0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 0, 5,
  0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
  
int4 RuleLexer::scanIdentifier(void)

{
  int4 i=0;
  identifier[i] = (char)getNextChar(); // Scan at least the first character
  i += 1;
  do {
    if ((identlist[next(0)]&1) != 0) {
      identifier[i] = (char) getNextChar();
      i += 1;
    }
    else
      break;
  } while(i<255);
  if ((i==255)||(i==0))
    return -1;			// Identifier is too long
  identifier[i] = '\0';
  identlength = i;

  if ((identlist[(int4)identifier[0]]&2) != 0) // First number is digit
    return scanNumber();

  switch(identifier[0]) {
  case 'o':
    return buildString(OP_IDENTIFIER);
  case 'v':
    return buildString(VAR_IDENTIFIER);
  case '#':
    return buildString(CONST_IDENTIFIER);
  case 'O':
    return buildString(OP_NEW_IDENTIFIER);
  case 'V':
    return buildString(VAR_NEW_IDENTIFIER);
  case '.':
    return buildString(DOT_IDENTIFIER);
  default:
    return otherIdentifiers();
  }
}
  
int4 RuleLexer::scanNumber(void)
  
{
  istringstream s(identifier);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  uint8 val;
  s >> val;
  if (!s)
    return BADINTEGER;
  ruleparselval.big = new int8(val);
  return INTB;
}

int4 RuleLexer::buildString(int4 tokentype)

{
  if (identlength <= 1) return -1;
  for(int4 i=1;i<identlength;++i) {
    if ((identlist[(int4)identifier[i]]&4)==0) return -1;
  }

  if (identifier[0] == '.') {
    ruleparselval.str = new string(identifier+1);
    return tokentype;
  }
    
  if (identifier[0] == '#')
    identifier[0] = 'c';
  ruleparselval.str = new string(identifier);
  return tokentype;
}

int4 RuleLexer::otherIdentifiers(void)

{
  map<string,int4>::const_iterator iter;
  iter = keywordmap.find(string(identifier));
  if (iter != keywordmap.end())
    return (*iter).second;
  return -1;
}

void RuleLexer::initKeywords(void)

{
  keywordmap["COPY"] = OP_COPY;
  keywordmap["ZEXT"] = OP_INT_ZEXT;
  keywordmap["CARRY"] = OP_INT_CARRY;
  keywordmap["SCARRY"] = OP_INT_SCARRY;
  keywordmap["SEXT"] = OP_INT_SEXT;
  keywordmap["SBORROW"] = OP_INT_SBORROW;
  keywordmap["NAN"] = OP_FLOAT_NAN;
  keywordmap["ABS"] = OP_FLOAT_ABS;
  keywordmap["SQRT"] = OP_FLOAT_SQRT;
  keywordmap["CEIL"] = OP_FLOAT_CEIL;
  keywordmap["FLOOR"] = OP_FLOAT_FLOOR;
  keywordmap["ROUND"] = OP_FLOAT_ROUND;
  keywordmap["INT2FLOAT"] = OP_FLOAT_INT2FLOAT;
  keywordmap["FLOAT2FLOAT"] = OP_FLOAT_FLOAT2FLOAT;
  keywordmap["TRUNC"] = OP_FLOAT_TRUNC;
  keywordmap["GOTO"] = OP_BRANCH;
  keywordmap["GOTOIND"] = OP_BRANCHIND;
  keywordmap["CALL"] = OP_CALL;
  keywordmap["CALLIND"] = OP_CALLIND;
  keywordmap["RETURN"] = OP_RETURN;
  keywordmap["CBRANCH"] = OP_CBRANCH;
  keywordmap["USEROP"] = OP_CALLOTHER;
  keywordmap["LOAD"] = OP_LOAD;
  keywordmap["STORE"] = OP_STORE;
  keywordmap["CONCAT"] = OP_PIECE;
  keywordmap["SUBPIECE"] = OP_SUBPIECE;
  keywordmap["before"] = BEFORE_KEYWORD;
  keywordmap["after"] = AFTER_KEYWORD;
  keywordmap["remove"] = REMOVE_KEYWORD;
  keywordmap["set"] = SET_KEYWORD;
  keywordmap["istrue"] = ISTRUE_KEYWORD;
  keywordmap["isfalse"] = ISFALSE_KEYWORD;
}

int4 RuleLexer::nextToken(void)

{
  for(;;) {
    int4 mychar = next(0);
    switch(mychar) {
    case '(':
    case ')':
    case ',':
    case '[':
    case ']':
    case ';':
    case '{':
    case '}':
    case ':':
      getNextChar();
      ruleparselval.ch = (char)mychar;
      return mychar;
    case '\r':
    case ' ':
    case '\t':
    case '\v':
      getNextChar();
      break;
    case '\n':
      getNextChar();
      lineno += 1;
      break;
    case '-':
      getNextChar();
      if (next(0) == '>') {
	getNextChar();
	return RIGHT_ARROW;
      }
      else if (next(0) == '-') {
	getNextChar();
	if (next(0) == '>') {
	  getNextChar();
	  return DOUBLE_RIGHT_ARROW;
	}
	return ACTION_TICK;
      }
      return OP_INT_SUB;
    case '<':
      getNextChar();
      if (next(0) == '-') {
	getNextChar();
	if (next(0) == '-') {
	  getNextChar();
	  return DOUBLE_LEFT_ARROW;
	}
	return LEFT_ARROW;
      }
      else if (next(0) == '<') {
	getNextChar();
	return OP_INT_LEFT;
      }
      else if (next(0) == '=') {
	getNextChar();
	return OP_INT_LESSEQUAL;
      }
      return OP_INT_LESS;
    case '|':
      getNextChar();
      if (next(0) == '|') {
	getNextChar();
	return OP_BOOL_OR;
      }
      return OP_INT_OR;
    case '&':
      getNextChar();
      if (next(0) == '&') {
	getNextChar();
	return OP_BOOL_AND;
      }
      return OP_INT_AND;
    case '^':
      getNextChar();
      if (next(0) == '^') {
	getNextChar();
	return OP_BOOL_XOR;
      }
      return OP_INT_XOR;
    case '>':
      if (next(1) == '>') {
	getNextChar();
	getNextChar();
	return OP_INT_RIGHT;
      }
      return -1;
    case '=':
      getNextChar();
      if (next(0) == '=') {
	getNextChar();
	return OP_INT_EQUAL;
      }
      ruleparselval.ch = (char)mychar;
      return mychar;
    case '!':
      getNextChar();
      if (next(0) == '=') {
	getNextChar();
	return OP_INT_NOTEQUAL;
      }
      return OP_BOOL_NEGATE;
    case 's':
      if (next(1) == '/') {
	getNextChar();
	getNextChar();
	return OP_INT_SDIV;
      }
      else if (next(1) == '%') {
	getNextChar();
	getNextChar();
	return OP_INT_SREM;
      }
      else if ((next(1)=='>')&&(next(2)=='>')) {
	getNextChar();
	getNextChar();
	getNextChar();
	return OP_INT_SRIGHT;
      }
      else if (next(1)=='<') {
	getNextChar();
	getNextChar();
	if (next(0) == '=') {
	  getNextChar();
	  return OP_INT_SLESSEQUAL;
	}
	return OP_INT_SLESS;
      }
      return scanIdentifier();
    case 'f':
      if (next(1) == '+') {
	getNextChar();
	getNextChar();
	return OP_FLOAT_ADD;
      }
      else if (next(1) == '-') {
	getNextChar();
	getNextChar();
	return OP_FLOAT_SUB;
      }
      else if (next(1) == '*') {
	getNextChar();
	getNextChar();
	return OP_FLOAT_MULT;
      }
      else if (next(1) == '/') {
	getNextChar();
	getNextChar();
	return OP_FLOAT_DIV;
      }
      else if ((next(1) == '=')&&(next(2) == '=')) {
	getNextChar();
	getNextChar();
	getNextChar();
	return OP_FLOAT_EQUAL;
      }
      else if ((next(1) == '!')&&(next(2) == '=')) {
	getNextChar();
	getNextChar();
	getNextChar();
	return OP_FLOAT_NOTEQUAL;
      }
      else if (next(1) == '<') {
	getNextChar();
	getNextChar();
	if (next(0) == '=') {
	  getNextChar();
	  return OP_FLOAT_LESSEQUAL;
	}
	return OP_FLOAT_LESS;
      }
      return -1;
    case '+':
      getNextChar();
      return OP_INT_ADD;
    case '*':
      getNextChar();
      return OP_INT_MULT;
    case '/':
      getNextChar();
      return OP_INT_DIV;
    case '%':
      getNextChar();
      return OP_INT_REM;
    case '~':
      getNextChar();
      return OP_INT_NEGATE;
    case '#':
      if ((identlist[next(1)]&6)==4)
	return scanIdentifier();
      getNextChar();
      ruleparselval.ch = (char)mychar; // Return '#' as single token
      return mychar;
    default:
      return scanIdentifier();
    }
  }
  return -1;
}

RuleLexer::RuleLexer(void)

{
  initKeywords();
}

void RuleLexer::initialize(istream &t)

{
  s = &t;
  pos = 0;
  endofstream = false;
  lineno = 1;
  getNextChar();
  getNextChar();
  getNextChar();
  getNextChar();		// Fill lookahead buffer
}

RuleCompile::RuleCompile(void)

{
  DummyTranslate dummy;
  error_stream = (ostream *)0;
  errors = 0;
  finalrule = (ConstraintGroup *)0;
  OpBehavior::registerInstructions(inst,&dummy);
}

RuleCompile::~RuleCompile(void)

{
  if (finalrule != (ConstraintGroup *)0)
    delete finalrule;
  for(int4 i=0;i<inst.size();++i) {
    OpBehavior *t_op = inst[i];
    if (t_op != (OpBehavior *)0)
      delete t_op;
  }
}

void RuleCompile::ruleError(const char *s)

{
  if (error_stream != (ostream *)0) {
    *error_stream << "Error at line " << dec << lexer.getLineNo() << endl;
    *error_stream << "   " << s << endl;
  }
  errors += 1;
}

int4 RuleCompile::findIdentifier(string *nm)

{
  int4 resid;
  map<string,int4>::const_iterator iter;
  iter = namemap.find(*nm);
  if (iter == namemap.end()) {
    resid = namemap.size();
    namemap[*nm] = resid;
  }
  else
   resid = (*iter).second;
  delete nm;
  return resid;
}

ConstraintGroup *RuleCompile::newOp(int4 id)

{
  ConstraintGroup *res = new ConstraintGroup();
  res->addConstraint(new DummyOpConstraint(id));
  return res;
}

ConstraintGroup *RuleCompile::newVarnode(int4 id)

{
  ConstraintGroup *res = new ConstraintGroup();
  res->addConstraint(new DummyVarnodeConstraint(id));
  return res;
}

ConstraintGroup *RuleCompile::newConst(int4 id)

{
  ConstraintGroup *res = new ConstraintGroup();
  res->addConstraint(new DummyConstConstraint(id));
  return res;
}

ConstraintGroup *RuleCompile::opCopy(ConstraintGroup *base,int4 opid)

{
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpCopy(opindex,opid);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opInput(ConstraintGroup *base,int8 *slot,int4 varid)

{
  int4 ourslot = (int4) *slot;
  delete slot;
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpInput(opindex,varid,ourslot);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opInputAny(ConstraintGroup *base,int4 varid)

{
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpInputAny(opindex,varid);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opInputConstVal(ConstraintGroup *base,int8 *slot,RHSConstant *val)

{
  int4 ourslot = (int4) *slot;
  delete slot;
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint;
  ConstantAbsolute *myconst = dynamic_cast<ConstantAbsolute *>(val);
  if (myconst != (ConstantAbsolute *)0) {
    newconstraint = new ConstraintParamConstVal(opindex,ourslot,myconst->getVal());
  }
  else {
    ConstantNamed *mynamed = dynamic_cast<ConstantNamed *>(val);
    if (mynamed != (ConstantNamed *)0) {
      newconstraint = new ConstraintParamConst(opindex,ourslot,mynamed->getId());
    }
    else {
      ruleError("Can only use absolute constant here");
      newconstraint = new ConstraintParamConstVal(opindex,ourslot,0);
    }
  }
  delete val;
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opOutput(ConstraintGroup *base,int4 varid)

{
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpOutput(opindex,varid);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varCopy(ConstraintGroup *base,int4 varid)

{
  int4 varindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintVarnodeCopy(varid,varindex);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varConst(ConstraintGroup *base,RHSConstant *ex,RHSConstant *sz)

{
  int4 varindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintVarConst(varindex,ex,sz);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varDef(ConstraintGroup *base,int4 opid)

{
  int4 varindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintDef(opid,varindex);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varDescend(ConstraintGroup *base,int4 opid)

{
  int4 varindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintDescend(opid,varindex);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varUniqueDescend(ConstraintGroup *base,int4 opid)

{
  int4 varindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintLoneDescend(opid,varindex);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opCodeConstraint(ConstraintGroup *base,vector<OpCode> *oplist)

{
  if (oplist->size() != 1)
    throw LowlevelError("Not currently supporting multiple opcode constraints");
  int4 opindex = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpcode(opindex,*oplist);
  delete oplist;
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::opCompareConstraint(ConstraintGroup *base,int4 opid,OpCode opc)

{
  int4 op1index = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintOpCompare(op1index,opid,(opc==CPUI_INT_EQUAL));
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::varCompareConstraint(ConstraintGroup *base,int4 varid,OpCode opc)

{
  int4 var1index = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintVarCompare(var1index,varid,(opc==CPUI_INT_EQUAL));
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::constCompareConstraint(ConstraintGroup *base,int4 constid,OpCode opc)

{
  int4 const1index = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintConstCompare(const1index,constid,opc);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::constNamedExpression(int4 id,RHSConstant *expr)

{
  ConstraintGroup *res = new ConstraintGroup();
  res->addConstraint(new ConstraintNamedExpression(id,expr));
  return res;
}

ConstraintGroup *RuleCompile::emptyGroup(void)

{
  return new ConstraintGroup();
}

ConstraintGroup *RuleCompile::emptyOrGroup(void)

{
  return new ConstraintOr();
}

ConstraintGroup *RuleCompile::mergeGroups(ConstraintGroup *a,ConstraintGroup *b)

{
  a->mergeIn(b);
  return a;
}

ConstraintGroup *RuleCompile::addOr(ConstraintGroup *base,ConstraintGroup *newor)

{
  base->addConstraint(newor);
  return base;
}

ConstraintGroup *RuleCompile::opCreation(int4 newid,OpCode oc,bool iafter,int4 oldid)

{
  OpBehavior *behave = inst[oc];
  int4 numparms = behave->isUnary() ? 1 : 2;
  UnifyConstraint *newconstraint = new ConstraintNewOp(newid,oldid,oc,iafter,numparms);
  ConstraintGroup *res = new ConstraintGroup();
  res->addConstraint(newconstraint);
  return res;
}

ConstraintGroup *RuleCompile::newUniqueOut(ConstraintGroup *base,int4 varid,int4 sz)

{
  UnifyConstraint *newconstraint = new ConstraintNewUniqueOut(base->getBaseIndex(),varid,sz);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::newSetInput(ConstraintGroup *base,RHSConstant *slot,int4 varid)

{
  UnifyConstraint *newconstraint = new ConstraintSetInput(base->getBaseIndex(),slot,varid);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::newSetInputConstVal(ConstraintGroup *base,RHSConstant *slot,RHSConstant *val,RHSConstant *sz)

{
  UnifyConstraint *newconstraint = new ConstraintSetInputConstVal(base->getBaseIndex(),slot,val,sz);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::removeInput(ConstraintGroup *base,RHSConstant *slot)

{
  UnifyConstraint *newconstraint = new ConstraintRemoveInput(base->getBaseIndex(),slot);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::newSetOpcode(ConstraintGroup *base,OpCode opc)

{
  int4 opid = base->getBaseIndex();
  UnifyConstraint *newconstraint = new ConstraintSetOpcode(opid,opc);
  base->addConstraint(newconstraint);
  return base;
}

ConstraintGroup *RuleCompile::booleanConstraint(bool ist,RHSConstant *expr)

{
  ConstraintGroup *base = new ConstraintGroup();
  UnifyConstraint *newconstraint = new ConstraintBoolean(ist,expr);
  base->addConstraint(newconstraint);
  return base;
}

RHSConstant *RuleCompile::constNamed(int4 id)

{
  RHSConstant *res = new ConstantNamed(id);
  return res;
}

RHSConstant *RuleCompile::constAbsolute(int8 *val)

{
  RHSConstant *res = new ConstantAbsolute(*val);
  delete val;
  return res;
}

RHSConstant *RuleCompile::constBinaryExpression(RHSConstant *ex1,OpCode opc,RHSConstant *ex2)

{
  RHSConstant *res = new ConstantExpression( ex1, ex2, opc );
  return res;
}

RHSConstant *RuleCompile::constVarnodeSize(int4 varindex)

{
  RHSConstant *res = new ConstantVarnodeSize(varindex);
  return res;
}

RHSConstant *RuleCompile::dotIdentifier(int4 id,string *str)

{
  RHSConstant *res;
  if ((*str) == "offset")
    res = new ConstantOffset(id);
  else if ((*str) == "size")
    res = new ConstantVarnodeSize(id);
  else if ((*str) == "isconstant")
    res = new ConstantIsConstant(id);
  else if ((*str) == "heritageknown")
    res = new ConstantHeritageKnown(id);
  else if ((*str) == "consume")
    res = new ConstantConsumed(id);
  else if ((*str) == "nzmask")
    res = new ConstantNZMask(id);
  else {
    string errmsg = "Unknown variable attribute: " + *str;
    ruleError(errmsg.c_str());
    res = new ConstantAbsolute(0);
  }
  delete str;
  return res;
}

void RuleCompile::run(istream &s,bool debug)

{
#ifdef YYDEBUG
  ruleparsedebug = debug ? 1 : 0;
#endif

  if (!s) {
    if (error_stream != (ostream *)0)
      *error_stream << "Bad input stream to rule compiler" << endl;
    return;
  }
  errors = 0;
  if (finalrule != (ConstraintGroup *)0) {
    delete finalrule;
    finalrule = (ConstraintGroup *)0;
  }
  lexer.initialize(s);

  rulecompile = this;		// Setup the global pointer
  int4 parseres = ruleparseparse(); // Try to parse
  if (parseres!=0) {
    errors += 1;
    if (error_stream != (ostream *)0)
      *error_stream << "Parsing error" << endl;
  }
    
  if (errors!=0) {
    if (error_stream != (ostream *)0)
      *error_stream << "Parsing incomplete" << endl;
  }
}

void RuleCompile::postProcess(void)

{
  int4 id = 0;
  finalrule->removeDummy();
  finalrule->setId(id);		// Set id for everybody
}

int4 RuleCompile::postProcessRule(vector<OpCode> &opcodelist)

{ // Do normal post processing but also remove initial opcode check
  finalrule->removeDummy();
  if (finalrule->numConstraints() == 0)
    throw LowlevelError("Cannot postprocess empty rule");
  ConstraintOpcode *subconst = dynamic_cast<ConstraintOpcode *>(finalrule->getConstraint(0));
  if (subconst == (ConstraintOpcode *)0)
    throw LowlevelError("Rule does not start with opcode constraint");
  opcodelist = subconst->getOpCodes();
  int4 opinit = subconst->getMaxNum();
  finalrule->deleteConstraint(0);
  int4 id = 0;
  finalrule->setId(id);
  return opinit;
}

ConstraintGroup *RuleCompile::buildUnifyer(const string &rule,const vector<string> &idlist,
					   vector<int4> &res)
{
  RuleCompile ruler;
  istringstream s(rule);
  ruler.run(s,false);
  if (ruler.numErrors() != 0)
    throw LowlevelError("Could not build rule");
  ConstraintGroup *resconst = ruler.releaseRule();
  for(int4 i=0;i<idlist.size();++i) {
    char initc;
    int4 id = -1;
    map<string,int4>::const_iterator iter;
    if (idlist[i].size() != 0) {
      initc = idlist[i][0];
      if ((initc == 'o')||(initc == 'O')||(initc == 'v')||(initc == 'V')||(initc == '#')) {
	iter = ruler.namemap.find(idlist[i]);
	if (iter != ruler.namemap.end())
	  id = (*iter).second;
      }
    }
    if (id == -1)
      throw LowlevelError("Bad initializer name: "+idlist[i]);
    res.push_back(id);
  }
  return resconst;
}

RuleGeneric::RuleGeneric(const string &g,const string &nm,const vector<OpCode> &sops,int4 opi,ConstraintGroup *c)
  : Rule(g,0,nm), state(c)
{
  starterops = sops;
  opinit = opi;
  constraint = c;
}

void RuleGeneric::getOpList(vector<uint4> &oplist) const

{
  for(int4 i=0;i<starterops.size();++i)
    oplist.push_back((uint4)starterops[i]);
}

int4 RuleGeneric::applyOp(PcodeOp *op,Funcdata &data)

{
  state.setFunction(&data);
  state.initialize(opinit,op);
  constraint->initialize(state);
  return constraint->step(state);
}

RuleGeneric *RuleGeneric::build(const string &nm,const string &gp,const string &content)

{
  RuleCompile compiler;
  istringstream s(content);
  compiler.run(s,false);
  if (compiler.numErrors() != 0)
    throw LowlevelError("Unable to parse dynamic rule: "+nm);
  
  vector<OpCode> opcodelist;
  int4 opinit = compiler.postProcessRule(opcodelist);
  RuleGeneric *res = new RuleGeneric(gp,nm,opcodelist,opinit,compiler.releaseRule());
  return res;
}

#endif

/* 

Here is the original flex parser

%{
#include "rulecompile.hh"
#include "ruleparse.hh"
#define ruleparsewrap() 1
#define YY_SKIP_YYWRAP

extern RuleCompile *rulecompile;

int4 scan_number(char *numtext,YYSTYPE *lval)

{
  istringstream s(numtext);
  s.unsetf(ios::dec | ios::hex | ios::oct);
  uintb val;
  s >> val;
  if (!s)
    return BADINTEGER;
  lval->big = new intb(val);
  return INTB;
}

int4 find_op_identifier(void)

{
  string ident(yytext);
  ruleparselval.id = rulecompile->findOpIdentifier(ident);
  return OP_IDENTIFIER;
}

int4 find_var_identifier(void)

{
  string ident(yytext);
  ruleparselval.id = rulecompile->findVarIdentifier(ident);
  return VAR_IDENTIFIER;
}

int4 find_const_identifier(void)

{
  string ident(yytext);
  ruleparselval.id = rulecompile->findConstIdentifier(ident);
  return CONST_IDENTIFIER;
}


%}

%%

[(),\[\];\{\}\#] { ruleparselval.ch = yytext[0]; return yytext[0]; }
[0-9]+     { return scan_number(yytext,&ruleparselval); }
0x[0-9a-fA-F]+  { return scan_number(yytext,&ruleparselval); }
[\r\ \t\v]+
\n         { rulecompile->nextLine(); }
\-\>          { return RIGHT_ARROW; }
\<\-          { return LEFT_ARROW; }
\|\|          { return OP_BOOL_OR; }
\&\&          { return OP_BOOL_AND; }
\^\^          { return OP_BOOL_XOR; }
\>\>          { return OP_INT_RIGHT; }
\<\<          { return OP_INT_LEFT; }
\=\=          { return OP_INT_EQUAL; }
\!\=          { return OP_INT_NOTEQUAL; }
\<\=          { return OP_INT_LESSEQUAL; }
s\/           { return OP_INT_SDIV; }
s\%           { return OP_INT_SREM; }
s\>\>         { return OP_INT_SRIGHT; }
s\<           { return OP_INT_SLESS; }
s\<\=         { return OP_INT_SLESSEQUAL; }
f\+           { return OP_FLOAT_ADD; }
f\-           { return OP_FLOAT_SUB; }
f\*           { return OP_FLOAT_MULT; }
f\/           { return OP_FLOAT_DIV; }
f\=\=         { return OP_FLOAT_EQUAL; }
f\!\=         { return OP_FLOAT_NOTEQUAL; }
f\<           { return OP_FLOAT_LESS; }
f\<\=         { return OP_FLOAT_LESSEQUAL; }
ZEXT          { return OP_INT_ZEXT; }
CARRY         { return OP_INT_CARRY; }
SEXT          { return OP_INT_SEXT; }
SCARRY        { return OP_INT_SCARRY; }
SBORROW       { return OP_INT_SBORROW; }
NAN           { return OP_FLOAT_NAN; }
ABS           { return OP_FLOAT_ABS; }
SQRT          { return OP_FLOAT_SQRT; }
CEIL          { return OP_FLOAT_CEIL; }
FLOOR         { return OP_FLOAT_FLOOR; }
ROUND         { return OP_FLOAT_ROUND; }
INT2FLOAT     { return OP_FLOAT_INT2FLOAT; }
FLOAT2FLOAT   { return OP_FLOAT_FLOAT2FLOAT; }
TRUNC         { return OP_FLOAT_TRUNC; }
GOTO          { return OP_BRANCH; }
GOTOIND       { return OP_BRANCHIND; }
CALL          { return OP_CALL; }
CALLIND       { return OP_CALLIND; }
RETURN        { return OP_RETURN; }
CBRRANCH      { return OP_CBRANCH; }
USEROP        { return OP_CALLOTHER; }
LOAD          { return OP_LOAD; }
STORE         { return OP_STORE; }
CONCAT        { return OP_PIECE; }
SUBPIECE      { return OP_SUBPIECE; }
\+            { return OP_INT_ADD; }
\-            { return OP_INT_SUB; }
\!            { return OP_BOOL_NEGATE; }
\&            { return OP_INT_AND; }
\|            { return OP_INT_OR; }
\^            { return OP_INT_XOR; }
\*            { return OP_INT_MULT; }
\/            { return OP_INT_DIV; }
\%            { return OP_INT_REM; }
\~            { return OP_INT_NEGATE; }
\<            { return OP_INT_LESS; }                 
o[a-zA-Z0-9_]+  { return find_op_identifier(); }
v[a-zA-Z0-9_]+  { return find_var_identifier(); }
#[a-zA-Z0-9_]+  { return find_const_identifier(); }

*/
