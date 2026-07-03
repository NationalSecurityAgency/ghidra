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
#include "pcodecompile.hh"

namespace ghidra {

/// \return the Location as a string
string Location::format(void) const

{
  ostringstream s;
  s << filename << ":" << dec << lineno;
  return s.str();
}

/// \param vn is the expression root
ExprTree::ExprTree(VarnodeTpl *vn)

{
  outvn = vn;
  ops = new vector<OpTpl *>;
}

ExprTree::~ExprTree(void)

{
  if (outvn != (VarnodeTpl *)0)
    delete outvn;
  if (ops != (vector<OpTpl *> *)0) {
    for(int4 i=0;i<ops->size();++i)
      delete (*ops)[i];
    delete ops;
  }
}

/// \brief Create a new \e raw expression by appending an array of VarnodeTpl, as inputs, to a new root OpTpl
///
/// The OpTpl may already have inputs.  The root VarnodeTpl from each ExprTree passed in is appended
/// to the list of input parameters of the OpTpl, creating a single new expression.
/// The original ExprTrees and their container are all destroyed.
/// The new expression is returned, in raw form, as a flattened array of OpTpl.
/// \param op is the new root OpTpl
/// \param param is the list of expressions, each with a root VarnodeTpl
/// \return the new \e raw expression as an array of OpTpl
vector<OpTpl *> *ExprTree::appendParams(OpTpl *op,vector<ExprTree *> *param)

{
  vector<OpTpl *> *res = new vector<OpTpl *>;
  
  for(int4 i=0;i<param->size();++i) {
    res->insert(res->end(),(*param)[i]->ops->begin(),(*param)[i]->ops->end());
    (*param)[i]->ops->clear();
    op->addInput((*param)[i]->outvn);
    (*param)[i]->outvn = (VarnodeTpl *)0;
    delete (*param)[i];
  }
  res->push_back(op);
  delete param;
  return res;
}

/// \brief Convert an expression to a raw array of OpTpl
///
/// The flattened array of OpTpl is stripped from the ExprTree, which is then destroyed.
/// \param expr is the expression to convert to an array
/// \return the raw array of OpTpl
vector<OpTpl *> *ExprTree::toVector(ExprTree *expr)

{
  vector<OpTpl *> *res = expr->ops;
  expr->ops = (vector<OpTpl *> *)0;
  delete expr;
  return res;
}

/// \param newout is the new output being forced
void ExprTree::setOutput(VarnodeTpl *newout)

{
  OpTpl *op;
  if (outvn == (VarnodeTpl *)0)
    throw SleighError("Expression has no output");
  if (outvn->isUnnamed()) {
    delete outvn;
    op = ops->back();
    op->clearOutput();
    op->setOutput(newout);
  }
  else {				// If the original output is named
    op = new OpTpl(CPUI_COPY);		// an extra COPY is required
    op->addInput(outvn);
    op->setOutput(newout);
    ops->push_back(op);
  }
  outvn = new VarnodeTpl(*newout);
}

/// \brief Force a size on a specific VarnodeTpl if possible
///
/// If the VarnodeTpl already has a fixed size, this method does nothing.
/// If the VarnodeTpl is a temporary register then all other temporaries with the same offset in the same expression
/// are also adjusted.
/// \param vt is the specific VarnodeTpl to adjust
/// \param size is the size constant to assign
/// \param ops is the array of OpTpl in the expression
void PcodeCompile::force_size(VarnodeTpl *vt,const ConstTpl &size,const vector<OpTpl *> &ops)

{
  if ((vt->getSize().getType()!=ConstTpl::real)||(vt->getSize().getReal() != 0))
    return;			// Size already exists

  vt->setSize(size);
  if (!vt->isLocalTemp()) return;
				// If the variable is a local temporary
				// The size may need to be propagated to the various
				// uses of the variable
  OpTpl *op;
  VarnodeTpl *vn;

  for(int4 i=0;i<ops.size();++i) {
    op = ops[i];
    vn = op->getOut();
    if ((vn!=(VarnodeTpl *)0)&&(vn->isLocalTemp())) {
      if (vn->getOffset() == vt->getOffset()) {
	if ((size.getType() == ConstTpl::real)&&(vn->getSize().getType() == ConstTpl::real)&&
	    (vn->getSize().getReal() != 0) && (vn->getSize().getReal() != size.getReal()))
	  throw SleighError("Localtemp size mismatch");
	vn->setSize(size);
      }
    }
    for(int4 j=0;j<op->numInput();++j) {
      vn = op->getIn(j);
      if (vn->isLocalTemp()&&(vn->getOffset()==vt->getOffset())) {
	if ((size.getType() == ConstTpl::real)&&(vn->getSize().getType() == ConstTpl::real)&&
	    (vn->getSize().getReal() != 0) && (vn->getSize().getReal() != size.getReal()))
	  throw SleighError("Localtemp size mismatch");
	vn->setSize(size);
      }
    }
  }
}

/// \brief Try to propagate a known size across a p-code operation to zero size inputs and outputs
///
/// If the OpTpl has an input (or output) VarnodeTpl with a know non-zero size, try to force this size
/// onto the VarnodeTpl in the indicated slot.
/// \param j is the slot we are trying to fill (-1=output)
/// \param op is the p-code operation to propagate the size across
/// \param inputonly indicates, if \b true, whether the size propagates only between inputs of the operation.
/// \param ops is an array of all operations in the sequence
void PcodeCompile::matchSize(int4 j,OpTpl *op,bool inputonly,const vector<OpTpl *> &ops)

{
  VarnodeTpl *match = (VarnodeTpl *)0;
  VarnodeTpl *vt;
  int4 i,inputsize;

  vt = (j==-1) ? op->getOut() : op->getIn(j);
  if (!inputonly) {
    if (op->getOut() != (VarnodeTpl *)0)
      if (!op->getOut()->isZeroSize())
	match = op->getOut();
  }
  inputsize = op->numInput();
  for(i=0;i<inputsize;++i) {
    if (match != (VarnodeTpl *)0) break;
    if (op->getIn(i)->isZeroSize()) continue;
    match = op->getIn(i);
  }
  if (match != (VarnodeTpl *)0)
    force_size(vt,match->getSize(),ops);
}

/// \brief Try to deduce the size of all input and output VarnodeTpl for the given OpTpl
///
/// For any VarnodeTpl whose size is not known (isZeroSize() returns \b true), an attempt is
/// made to fill in the size from another input or output of the OpTpl.
/// \param op is the given OpTpl
/// \param ops is the complete set of OpTpl in the expression/constructor
void PcodeCompile::fillinZero(OpTpl *op,const vector<OpTpl *> &ops)

{
  int4 inputsize,i;

  switch(op->getOpcode()) {
  case CPUI_COPY:			// Instructions where all inputs and output are same size
  case CPUI_INT_ADD:
  case CPUI_INT_SUB:
  case CPUI_INT_2COMP:
  case CPUI_INT_NEGATE:
  case CPUI_INT_XOR:
  case CPUI_INT_AND:
  case CPUI_INT_OR:
  case CPUI_INT_MULT:
  case CPUI_INT_DIV:
  case CPUI_INT_SDIV:
  case CPUI_INT_REM:
  case CPUI_INT_SREM:
  case CPUI_FLOAT_ADD:
  case CPUI_FLOAT_DIV:
  case CPUI_FLOAT_MULT:
  case CPUI_FLOAT_SUB:
  case CPUI_FLOAT_NEG:
  case CPUI_FLOAT_ABS:
  case CPUI_FLOAT_SQRT:
  case CPUI_FLOAT_CEIL:
  case CPUI_FLOAT_FLOOR:
  case CPUI_FLOAT_ROUND:
    if ((op->getOut()!=(VarnodeTpl *)0)&&(op->getOut()->isZeroSize()))
      matchSize(-1,op,false,ops);
    inputsize = op->numInput();
    for(i=0;i<inputsize;++i)
      if (op->getIn(i)->isZeroSize())
	matchSize(i,op,false,ops);
    break;
  case CPUI_INT_EQUAL:		// Instructions with bool output
  case CPUI_INT_NOTEQUAL:
  case CPUI_INT_SLESS:
  case CPUI_INT_SLESSEQUAL:
  case CPUI_INT_LESS:
  case CPUI_INT_LESSEQUAL:
  case CPUI_INT_CARRY:
  case CPUI_INT_SCARRY:
  case CPUI_INT_SBORROW:
  case CPUI_FLOAT_EQUAL:
  case CPUI_FLOAT_NOTEQUAL:
  case CPUI_FLOAT_LESS:
  case CPUI_FLOAT_LESSEQUAL:
  case CPUI_FLOAT_NAN:
  case CPUI_BOOL_NEGATE:
  case CPUI_BOOL_XOR:
  case CPUI_BOOL_AND:
  case CPUI_BOOL_OR:
    if (op->getOut()->isZeroSize())
      force_size(op->getOut(),ConstTpl(ConstTpl::real,1),ops);
    inputsize = op->numInput();
    for(i=0;i<inputsize;++i)
      if (op->getIn(i)->isZeroSize())
	matchSize(i,op,true,ops);
    break;
    // The shift amount does not necessarily have to be the same size
    // But if no size is specified, assume it is the same size
  case CPUI_INT_LEFT:
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:
    if (op->getOut()->isZeroSize()) {
      if (!op->getIn(0)->isZeroSize())
	force_size(op->getOut(),op->getIn(0)->getSize(),ops);
    }
    else if (op->getIn(0)->isZeroSize())
      force_size(op->getIn(0),op->getOut()->getSize(),ops);
    // fallthru to subpiece constant check
  case CPUI_SUBPIECE:
    if (op->getIn(1)->isZeroSize())
      force_size(op->getIn(1),ConstTpl(ConstTpl::real,4),ops);
    break;
  case CPUI_CPOOLREF:
    if (op->getOut()->isZeroSize() && (!op->getIn(0)->isZeroSize()))
      force_size(op->getOut(),op->getIn(0)->getSize(),ops);
    if (op->getIn(0)->isZeroSize() && (!op->getOut()->isZeroSize()))
      force_size(op->getIn(0),op->getOut()->getSize(),ops);
    for(i=1;i<op->numInput();++i) {
      if (op->getIn(i)->isZeroSize())
	force_size(op->getIn(i),ConstTpl(ConstTpl::real,sizeof(uintb)),ops);
    }
    break;
  default:
    break;
  }
}

/// \brief Propagate a size to all VarnodeTpl whose size is unknown
///
/// Size information is propagated across operations and expressions as far as possible.
/// If there are any remaining VarnodeTpl whose size is unknown, return \b false.
/// \param ct is the set of p-code operations to propagate across
/// \return \b true if all VarnodeTpl have a known size
bool PcodeCompile::propagateSize(ConstructTpl *ct)

{
  vector<OpTpl *> zerovec,zerovec2;
  vector<OpTpl *>::const_iterator iter;
  int4 lastsize;

  for(iter=ct->getOpvec().begin();iter!=ct->getOpvec().end();++iter)
    if ((*iter)->isZeroSize()) {
      fillinZero(*iter,ct->getOpvec());
      if ((*iter)->isZeroSize())
	zerovec.push_back(*iter);
    }
  lastsize = zerovec.size() + 1;
  while( zerovec.size() < lastsize ) {
    lastsize = zerovec.size();
    zerovec2.clear();
    for(iter=zerovec.begin();iter!=zerovec.end();++iter) {
      fillinZero(*iter,ct->getOpvec());
      if ((*iter)->isZeroSize())
	zerovec2.push_back( *iter );
    }
    zerovec = zerovec2;
  }
  if ( lastsize != 0 ) return false;
  return true;
}

/// Space for the register is allocated in the \e unique address space.
/// \return the new temporary register
VarnodeTpl *PcodeCompile::buildTemporary(void)

{
  VarnodeTpl *res = new VarnodeTpl(ConstTpl(uniqspace),
				   ConstTpl(ConstTpl::real,allocateTemp()),
				   ConstTpl(ConstTpl::real,0));
  res->setUnnamed(true);
  return res;
}

/// The parsed name and the next available id are assigned to the label. The symbol is assigned to the current scope.
/// \param name is the parsed name of the label
/// \return the new symbol
LabelSymbol *PcodeCompile::defineLabel(string *name)

{
  LabelSymbol *labsym = new LabelSymbol(*name,local_labelcount++);
  delete name;
  addSymbol(labsym);		// Add symbol to local scope
  return labsym;
}

/// A placeholder OpTpl for the label is created and returned, as an array.
/// \param labsym is the given label
/// \return an array containing the new OpTpl
vector<OpTpl *> *PcodeCompile::placeLabel(LabelSymbol *labsym)

{
  if (labsym->isPlaced()) {
    reportError(getLocation(labsym), "Label '" + labsym->getName() + "' is placed more than once");
  }
  labsym->setPlaced();
  vector<OpTpl *> *res = new vector<OpTpl *>;
  OpTpl *op = new OpTpl(LABELBUILD);
  VarnodeTpl *idvn = new VarnodeTpl(ConstTpl(constantspace),
				      ConstTpl(ConstTpl::real,labsym->getIndex()),
				      ConstTpl(ConstTpl::real,4));
  op->addInput(idvn);
  res->push_back(op);
  return res;
}

/// A new named temporary register is created and assigned as the root of the given expression.
/// A symbol representing the register is added to the current scope.
/// \param usesLocalKey is \b true if the name was defined with the 'local' keyword
/// \param rhs is the given expression
/// \param varname is the parsed symbol name to associate with the new register
/// \param size is non-zero if an explicit size was provided in the parsed definition
/// \return the new expression as a raw array of OpTpl
vector<OpTpl *> *PcodeCompile::newOutput(bool usesLocalKey,ExprTree *rhs,string *varname,uint4 size)

{
  VarnodeSymbol *sym;
  VarnodeTpl *tmpvn = buildTemporary();
  if (size != 0)
    tmpvn->setSize(ConstTpl(ConstTpl::real,size)); // Size was explicitly specified
  else if ((rhs->getSize().getType()==ConstTpl::real)&&(rhs->getSize().getReal()!=0))
    tmpvn->setSize(rhs->getSize());	// Inherit size from unnamed expression result
				// Only inherit if the size is real, otherwise we
				// cannot build the VarnodeSymbol with a placeholder constant
  rhs->setOutput(tmpvn);
  sym = new VarnodeSymbol(*varname,tmpvn->getSpace().getSpace(),tmpvn->getOffset().getReal(),tmpvn->getSize().getReal()); // Create new symbol regardless
  addSymbol(sym);
  if ((!usesLocalKey) && enforceLocalKey)
    reportError(getLocation(sym), "Must use 'local' keyword to define symbol '"+*varname + "'");
  delete varname;
  return ExprTree::toVector(rhs);
}

/// A temporary register is allocated, and the symbol is added to the current scope.
/// \param varname is the parsed symbol name
/// \param size is the size of the new register (0 indicates the size is initially unknown)
void PcodeCompile::newLocalDefinition(string *varname,uint4 size)

{
  VarnodeSymbol *sym;
  sym = new VarnodeSymbol(*varname,uniqspace,allocateTemp(),size);
  addSymbol(sym);
  delete varname;
}

/// A new expression is created ending in a unary operation.
/// The input to the operation is the root VarnodeTpl of the given expression,
/// and the output is a new temporary register.
/// \param opc is the unary operation code
/// \param vn is the given input expression
/// \return the new expression
ExprTree *PcodeCompile::createOp(OpCode opc,ExprTree *vn)

{
  VarnodeTpl *outvn = buildTemporary();
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  op->setOutput(outvn);
  vn->ops->push_back(op);
  vn->outvn = new VarnodeTpl(*outvn);
  return vn;
}

/// A new expression is created ending in a binary operation.
/// Inputs to the operation are the root VarnodeTpl from the two given expressions,
/// and the output is a new temporary register.
/// \param opc is the binary operation code
/// \param vn1 is the first input expression
/// \param vn2 is the second input expression
/// \return the new combined expression
ExprTree *PcodeCompile::createOp(OpCode opc,ExprTree *vn1,ExprTree *vn2)

{
  VarnodeTpl *outvn = buildTemporary();
  vn1->ops->insert(vn1->ops->end(),vn2->ops->begin(),vn2->ops->end());
  vn2->ops->clear();
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn1->outvn);
  op->addInput(vn2->outvn);
  vn2->outvn = (VarnodeTpl *)0;
  op->setOutput(outvn);
  vn1->ops->push_back(op);
  vn1->outvn = new VarnodeTpl(*outvn);
  delete vn2;
  return vn1;
}

/// \brief Create a new binary operation combining the given input expressions and an explicit output VarnodeTpl
///
/// A new expression is created ending in a binary operation.
/// Inputs are the root VarnodeTpl from the two given expressions.
/// \param outvn is the explicit output of the new operation
/// \param opc is the binary operation code
/// \param vn1 is the first input expression
/// \param vn2 is the second input expression
/// \return the new combined expression
ExprTree *PcodeCompile::createOpOut(VarnodeTpl *outvn,OpCode opc,
				       ExprTree *vn1,ExprTree *vn2)
{
  vn1->ops->insert(vn1->ops->end(),vn2->ops->begin(),vn2->ops->end());
  vn2->ops->clear();
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn1->outvn);
  op->addInput(vn2->outvn);
  vn2->outvn = (VarnodeTpl *)0;
  op->setOutput(outvn);
  vn1->ops->push_back(op);
  vn1->outvn = new VarnodeTpl(*outvn);
  delete vn2;
  return vn1;
}

/// \brief Create a new unary operation with the given expression as input and an explicit output VarnodeTpl
///
/// A new expression is created ending in a unary operation.
/// The input to the operation is the root VarnodeTpl of the given expression.
/// \param outvn is the explicit output of the new operation
/// \param opc is the unary operation code
/// \param vn is the input expression
/// \return the new combined expression
ExprTree *PcodeCompile::createOpOutUnary(VarnodeTpl *outvn,OpCode opc,ExprTree *vn)

{
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  op->setOutput(outvn);
  vn->ops->push_back(op);
  vn->outvn = new VarnodeTpl(*outvn);
  return vn;
}

/// \brief Create a new unary operation with the given expression as input and no output
///
/// A new expression is created ending in a unary operation.
/// The input to the operation is the root VarnodeTpl of the given expression.
/// \param opc is the unary operation code
/// \param vn is the input expression
/// \return the new combined expression as raw array
vector<OpTpl *> *PcodeCompile::createOpNoOut(OpCode opc,ExprTree *vn)

{
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  vn->outvn = (VarnodeTpl *)0;	// There is no longer an output to this expression
  vector<OpTpl *> *res = vn->ops;
  vn->ops = (vector<OpTpl *> *)0;
  delete vn;
  res->push_back(op);
  return res;
}

/// \brief Create a new binary operation with the given expressions as input and no output
///
/// A new expression is created ending in a binary operation.
/// Inputs are the root VarnodeTpl of the given expressions.
/// \param opc is the binary operation code
/// \param vn1 is the first input expression
/// \param vn2 is the second input expression
/// \return the new combined expression as a raw array
vector<OpTpl *> *PcodeCompile::createOpNoOut(OpCode opc,ExprTree *vn1,ExprTree *vn2)

{
  vector<OpTpl *> *res = vn1->ops;
  vn1->ops = (vector<OpTpl *> *)0;
  res->insert(res->end(),vn2->ops->begin(),vn2->ops->end());
  vn2->ops->clear();
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn1->outvn);
  vn1->outvn = (VarnodeTpl *)0;
  op->addInput(vn2->outvn);
  vn2->outvn = (VarnodeTpl *)0;
  res->push_back(op);
  delete vn1;
  delete vn2;
  return res;
}

/// \brief Create a new unary operation with the given constant as input and no output.
///
/// A new expression is created ending in a unary operation.
/// A new constant VarnodeTpl is created as input.
/// \param opc is the unary operation code
/// \param val is the constant value of the input
/// \return the new expression as a raw array
vector<OpTpl *> *PcodeCompile::createOpConst(OpCode opc,uintb val)

{
  VarnodeTpl *vn = new VarnodeTpl(ConstTpl(constantspace),
				    ConstTpl(ConstTpl::real,val),
				    ConstTpl(ConstTpl::real,4));
  vector<OpTpl *> *res = new vector<OpTpl *>;
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn);
  res->push_back(op);
  return res;
}

/// \brief Create a new LOAD operation with the given pointer expression as input
///
/// A new expression is created ending in a LOAD operation.
/// The input pointer is the root VarnodeTpl of the given expression.
/// The output is a new temporary register.
/// \param qual provides the address space and any knowledge of the size being LOADed
/// \param ptr is the given pointer expression
/// \return the new expression
ExprTree *PcodeCompile::createLoad(StarQuality *qual,ExprTree *ptr)

{
  VarnodeTpl *outvn = buildTemporary();
  OpTpl *op = new OpTpl(CPUI_LOAD);
  // The first varnode input to the load is a constant reference to the AddrSpace being loaded
  // from.  Internally, we really store the pointer to the AddrSpace as the reference, but this
  // isn't platform independent. So officially, we assume that the constant reference will be the
  // AddrSpace index.  We can safely assume this always has size 4.
  VarnodeTpl *spcvn = new VarnodeTpl(ConstTpl(constantspace),
				     qual->id,
				     ConstTpl(ConstTpl::real,8));
  op->addInput(spcvn);
  op->addInput(ptr->outvn);
  op->setOutput(outvn);
  ptr->ops->push_back(op);
  if (qual->size > 0)
    force_size(outvn,ConstTpl(ConstTpl::real,qual->size),*ptr->ops);
  ptr->outvn = new VarnodeTpl(*outvn);
  delete qual;
  return ptr;
}

/// \brief Create a new STORE operation with the given expressions as inputs
///
/// A new expression is created ending in a STORE operation.
/// The inputs are the root VarnodeTpl of the given expressions.
/// \param qual provides the address space and any knowledge of the size being STOREed
/// \param ptr is the pointer expression
/// \param val is the value being STOREd
/// \return the new expression as a raw array
vector<OpTpl *> *PcodeCompile::createStore(StarQuality *qual,ExprTree *ptr,ExprTree *val)

{
  vector<OpTpl *> *res = ptr->ops;
  ptr->ops = (vector<OpTpl *> *)0;
  res->insert(res->end(),val->ops->begin(),val->ops->end());
  val->ops->clear();
  OpTpl *op = new OpTpl(CPUI_STORE);
  // The first varnode input to the store is a constant reference to the AddrSpace being loaded
  // from.  Internally, we really store the pointer to the AddrSpace as the reference, but this
  // isn't platform independent. So officially, we assume that the constant reference will be the
  // AddrSpace index.  We can safely assume this always has size 4.
  VarnodeTpl *spcvn = new VarnodeTpl(ConstTpl(constantspace),
				     qual->id,
				     ConstTpl(ConstTpl::real,8));
  op->addInput(spcvn);
  op->addInput(ptr->outvn);
  op->addInput(val->outvn);
  res->push_back(op);
  force_size(val->outvn,ConstTpl(ConstTpl::real,qual->size),*res);
  ptr->outvn = (VarnodeTpl *)0;
  val->outvn = (VarnodeTpl *)0;
  delete ptr;
  delete val;
  delete qual;
  return res;
}

/// \brief Create a CALLOTHER p-code op with temporary output, given a symbol and parameter expressions
///
/// A new expression is created ending in a CALLOTHER operation.
/// Inputs are the root VarnodeTpl from the given array of expressions.
/// The output is a new temporary register.
/// \param sym is the symbol to associate with CALLOTHER
/// \param param is the array of input expressions
/// \return the new combined expression
ExprTree *PcodeCompile::createUserOp(UserOpSymbol *sym,vector<ExprTree *> *param)

{
  VarnodeTpl *outvn = buildTemporary();
  ExprTree *res = new ExprTree();
  res->ops = createUserOpNoOut(sym,param);
  res->ops->back()->setOutput(outvn);
  res->outvn = new VarnodeTpl(*outvn);
  return res;
}

/// \brief Create a CALLOTHER p-code op, given a symbol and parameter expressions
///
/// A new expression is created ending in a CALLOTHER operation, with no output.
/// Inputs are the root VarnodeTpl from the given array of expressions.
/// \param sym is the symbol to associate with the CALLOTHER
/// \param param is the array of input expressions
/// \return the new combined expression as a raw array
vector<OpTpl *> *PcodeCompile::createUserOpNoOut(UserOpSymbol *sym,vector<ExprTree *> *param)

{
  OpTpl *op = new OpTpl(CPUI_CALLOTHER);
  VarnodeTpl *vn = new VarnodeTpl(ConstTpl(constantspace),
				    ConstTpl(ConstTpl::real,sym->getIndex()),
				    ConstTpl(ConstTpl::real,4));
  op->addInput(vn);
  return ExprTree::appendParams(op,param);
}

/// \brief Create a new operation with a variable number of inputs and a temporary output.
///
/// A new expression is created ending in the new operation.
/// Inputs are the root VarnodeTpl from the given array of expressions.
/// The output is a new temporary register.
/// \param opc is the variadic operation code
/// \param param is the array of input expressions
/// \return the new combined expression
ExprTree *PcodeCompile::createVariadic(OpCode opc,vector<ExprTree *> *param)

{
  VarnodeTpl *outvn = buildTemporary();
  ExprTree *res = new ExprTree();
  OpTpl *op = new OpTpl(opc);
  res->ops = ExprTree::appendParams(op,param);
  res->ops->back()->setOutput(outvn);
  res->outvn = new VarnodeTpl(*outvn);
  return res;
}

/// \brief Append a binary operation to the given expression.
///
/// A new operation is appended to the end of the expression.
/// The root VarnodeTpl of the expression becomes the first input to the operation.
/// The given constant value and size becomes the second input.
/// \param opc is the binary operation code
/// \param res is the expression being modified and the first input
/// \param constval is the second input value
/// \param constsz is the second input size
void PcodeCompile::appendOp(OpCode opc,ExprTree *res,uintb constval,int4 constsz)

{
  OpTpl *op = new OpTpl(opc);
  VarnodeTpl *constvn = new VarnodeTpl(ConstTpl(constantspace),
					 ConstTpl(ConstTpl::real,constval),
					 ConstTpl(ConstTpl::real,constsz));
  VarnodeTpl *outvn = buildTemporary();
  op->addInput(res->outvn);
  op->addInput(constvn);
  op->setOutput(outvn);
  res->ops->push_back(op);
  res->outvn = new VarnodeTpl(*outvn);
}

/// \brief Build a truncated VarnodeTpl, if possible, from the given bit range
///
/// The bit range must be on byte boundaries or NULL is returned.
/// The VarnodeTpl being must already have fixed dimensions or be a \b handle.
/// For a \b handle, the truncation is built using ConstTpl::v_offset_plus mechanics, allowing the
/// truncation for exported values to be computed in the context of a specific instruction.
/// \param basevn is the VarnodeTpl to be truncated
/// \param bitoffset is the starting bit of the range (0 indicates the least significant bit)
/// \param numbits is the number of bits in the range
/// \return the truncated VarnodeTpl (or NULL)
VarnodeTpl *PcodeCompile::buildTruncatedVarnode(VarnodeTpl *basevn,uint4 bitoffset,uint4 numbits)

{
  uint4 byteoffset = bitoffset / 8; // Convert to byte units
  uint4 numbytes = numbits / 8;
  uintb fullsz = 0;
  if (basevn->getSize().getType() == ConstTpl::real) {
    // If we know the size of base, make sure the bit range is in bounds
    fullsz = basevn->getSize().getReal();
    if (fullsz == 0) return (VarnodeTpl *)0;
    if (byteoffset + numbytes > fullsz)
      throw SleighError("Requested bit range out of bounds");
  }

  if ((bitoffset % 8) != 0) return (VarnodeTpl *)0;
  if ((numbits % 8) != 0) return (VarnodeTpl *)0;

  ConstTpl::const_type offset_type = basevn->getOffset().getType();
  if ((offset_type != ConstTpl::real)&&(offset_type != ConstTpl::handle))
    return (VarnodeTpl *)0;

  ConstTpl specialoff;
  if (offset_type == ConstTpl::handle) {
    // We put in the correct adjustment to offset assuming things are little endian
    // We defer the correct big endian calculation until after the consistency check
    // because we need to know the subtable export sizes
    specialoff = ConstTpl(ConstTpl::handle,basevn->getOffset().getHandleIndex(),
			  ConstTpl::v_offset_plus,byteoffset);
  }
  else { 
    if (basevn->getSize().getType() != ConstTpl::real)
      throw SleighError("Could not construct requested bit range");
    uintb plus;
    if (defaultspace->isBigEndian())
      plus = fullsz - (byteoffset + numbytes);
    else
      plus = byteoffset;
    specialoff = ConstTpl(ConstTpl::real,basevn->getOffset().getReal() + plus);
  }
  VarnodeTpl *res = new VarnodeTpl(basevn->getSpace(),specialoff,ConstTpl(ConstTpl::real,numbytes));
  return res;
}

/// \brief Assign an expression to a bit range within a given VarnodeTpl
///
/// Other bits of the VarnodeTpl are preserved.  The value assigned is taken from the root VarnodeTpl
/// of the expression, which is assumed to have zero bits in any position greater than or equal to \b numbits.
/// If the bit range falls on byte boundaries, the assignment is accomplished with byte based truncation operations.
/// Otherwise mask and shift operations (INT_AND, INT_OR, and INT_LEFT) are used.
/// \param vn is the given VarnodeTpl being assigned to
/// \param bitoffset is the starting bit of the range (0 indicates the least significant bit)
/// \param numbits is the number of bits in the range
/// \param rhs is the expression being assigned
/// \return a new combined expression as a raw array
vector<OpTpl *> *PcodeCompile::assignBitRange(VarnodeTpl *vn,uint4 bitoffset,uint4 numbits,ExprTree *rhs)

{
  string errmsg;
  if (numbits == 0)
    errmsg = "Size of bitrange is zero";
  uint4 smallsize = (numbits+7)/8; // Size of input (output of rhs)
  bool shiftneeded = (bitoffset != 0);
  bool zextneeded = true;
  uintb mask = (uintb)2;
  mask = ~(((mask<<(numbits-1))-1) << bitoffset);

  if (vn->getSize().getType()==ConstTpl::real) {
    // If we know the size of the bitranged varnode, we can
    // do some immediate checks, and possibly simplify things
    uint4 symsize = vn->getSize().getReal();
    if (symsize > 0)
      zextneeded = (symsize > smallsize);
    symsize *= 8;		// Convert to number of bits
    if ((bitoffset>=symsize)||(bitoffset+numbits>symsize))
      errmsg = "Assigned bitrange is bad";
    else if ((bitoffset==0)&&(numbits==symsize))
      errmsg = "Assigning to bitrange is superfluous";
  }

  if (errmsg.size()>0) {	// Was there an error condition
    reportError((const Location *)0, errmsg);	// Report the error
    delete vn;			// Clean up
    vector<OpTpl *> *resops = rhs->ops; // Passthru old expression
    rhs->ops = (vector<OpTpl *> *)0;
    delete rhs;
    return resops;
  }

  // We know what the size of the input has to be
  force_size(rhs->outvn,ConstTpl(ConstTpl::real,smallsize),*rhs->ops);

  ExprTree *res;
  VarnodeTpl *finalout = buildTruncatedVarnode(vn,bitoffset,numbits);
  if (finalout != (VarnodeTpl *)0) {
    delete vn;	// Don't keep the original Varnode object
    res = createOpOutUnary(finalout,CPUI_COPY,rhs);
  }
  else {
    if (bitoffset + numbits > 64)
      errmsg = "Assigned bitrange extends past first 64 bits";
    res = new ExprTree(vn);
    appendOp(CPUI_INT_AND,res,mask,0);
    if (zextneeded)
      createOp(CPUI_INT_ZEXT,rhs);
    if (shiftneeded)
      appendOp(CPUI_INT_LEFT,rhs,bitoffset,4);
  
    finalout = new VarnodeTpl(*vn);
    res = createOpOut(finalout,CPUI_INT_OR,res,rhs);
  }
  if (errmsg.size() > 0)
    reportError((const Location *)0, errmsg);
  vector<OpTpl *> *resops = res->ops;
  res->ops = (vector<OpTpl *> *)0;
  delete res;
  return resops;
}

/// \brief Create an expression computing the indicated bit range of a symbol
///
/// The result is truncated to the smallest byte size that can contain the indicated number of bits,
/// with the desired bits shifted into the least significant positions.
/// If the bit range is on byte boundaries, the truncation is accomplished with byte based truncation operations.
/// Otherwise masks and shifts (INT_AND and INT_RIGHT) are used.
/// \param sym is the symbol representing the VarnodeTpl to truncate
/// \param bitoffset is the starting bit of the range (0 indicates the least significant bit)
/// \param numbits is the number of bits in the range
/// \return a new expression whose root VarnodeTpl holds the result
ExprTree *PcodeCompile::createBitRange(SpecificSymbol *sym,uint4 bitoffset,uint4 numbits)

{
  string errmsg;
  if (numbits == 0)
    errmsg = "Size of bitrange is zero";
  VarnodeTpl *vn = sym->getVarnode();
  uint4 finalsize = (numbits+7)/8; // Round up to neareast byte size
  uint4 truncshift = 0;
  bool maskneeded = ((numbits%8)!=0);
  bool truncneeded = true;

  // Special case where we can set the size, without invoking
  // a truncation operator
  if ((errmsg.size()==0)&&(bitoffset==0)&&(!maskneeded)) {
    if ((vn->getSpace().getType()==ConstTpl::handle)&&vn->isZeroSize()) {
      vn->setSize(ConstTpl(ConstTpl::real,finalsize));
      ExprTree *res = new ExprTree(vn);
      //      VarnodeTpl *cruft = buildTemporary();
      //      delete cruft;
      return res;
    }
  }

  if (errmsg.size()==0) {
    VarnodeTpl *truncvn = buildTruncatedVarnode(vn,bitoffset,numbits);
    if (truncvn != (VarnodeTpl *)0) { // If we are able to construct a simple truncated varnode
      ExprTree *res = new ExprTree(truncvn); // Return just the varnode as an expression
      delete vn;
      return res;
    }
  }

  if (vn->getSize().getType()==ConstTpl::real) {
    // If we know the size of the input varnode, we can
    // do some immediate checks, and possibly simplify things
    uint4 insize = vn->getSize().getReal();
    if (insize > 0) {
      truncneeded = (finalsize < insize);
      insize *= 8;		// Convert to number of bits
      if ((bitoffset >= insize)||(bitoffset+numbits > insize))
	errmsg = "Bitrange is bad";
      if (maskneeded && ((bitoffset+numbits)==insize))
	maskneeded = false;
    }
  }

  uintb mask = (uintb)2;
  mask = ((mask<<(numbits-1))-1);
  
  if (truncneeded && ((bitoffset % 8)==0)) {
    truncshift = bitoffset/8;
    bitoffset = 0;
  }

  if ((bitoffset==0)&&(!truncneeded)&&(!maskneeded))
    errmsg = "Superfluous bitrange";

  if (maskneeded && (finalsize > 8))
    errmsg = "Illegal masked bitrange producing varnode larger than 64 bits: " + sym->getName();

  ExprTree *res = new ExprTree(vn);

  if (errmsg.size()>0) {	// Check for error condition
    reportError(getLocation(sym), errmsg);
    return res;
  }

  if (bitoffset !=0)
    appendOp(CPUI_INT_RIGHT,res,bitoffset,4);
  if (truncneeded)
    appendOp(CPUI_SUBPIECE,res,truncshift,4);
  if (maskneeded)
    appendOp(CPUI_INT_AND,res,mask,finalsize);
  force_size(res->outvn,ConstTpl(ConstTpl::real,finalsize),*res->ops);
  return res;
}

/// \brief Produce a constant VarnodeTpl that is the offset of the storage address of the given VarnodeTpl
///
/// \param var is the given VarnodeTpl to take the address of
/// \param size is the size of the resulting pointer constant (may be 0)
/// \return the new constant VarnodeTpl
VarnodeTpl *PcodeCompile::addressOf(VarnodeTpl *var,uint4 size)

{
  if (size==0) {		// If no size specified
    if (var->getSpace().getType() == ConstTpl::spaceid) {
      AddrSpace *spc = var->getSpace().getSpace();	// Look to the particular space
      size = spc->getAddrSize(); // to see if it has a standard address size
    }
  }
  VarnodeTpl *res;
  if ((var->getOffset().getType() == ConstTpl::real)&&(var->getSpace().getType() == ConstTpl::spaceid)) {
    AddrSpace *spc = var->getSpace().getSpace();
    uintb off = AddrSpace::byteToAddress(var->getOffset().getReal(),spc->getWordSize());
    res = new VarnodeTpl(ConstTpl(constantspace),
			  ConstTpl(ConstTpl::real,off),
			  ConstTpl(ConstTpl::real,size));
  }
  else
    res = new VarnodeTpl(ConstTpl(constantspace),var->getOffset(),ConstTpl(ConstTpl::real,size));
  delete var;
  return res;
}

} // End namespace ghidra
