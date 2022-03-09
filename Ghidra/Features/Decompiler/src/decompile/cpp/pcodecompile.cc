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

string Location::format(void) const

{
  ostringstream s;
  s << filename << ":" << dec << lineno;
  return s.str();
}

  ExprTree::ExprTree(VarnodeTpl *vn)

{
  outvn = vn;
  ops = new vector<OpTpl *>;
}

ExprTree::ExprTree(OpTpl *op)

{
  ops = new vector<OpTpl *>;
  ops->push_back(op);
  if (op->getOut() != (VarnodeTpl *)0)
    outvn = new VarnodeTpl(*op->getOut());
  else
    outvn = (VarnodeTpl *)0;
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

vector<OpTpl *> *ExprTree::appendParams(OpTpl *op,vector<ExprTree *> *param)

{				// Create op expression with entire list of expression
				// inputs
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

vector<OpTpl *> *ExprTree::toVector(ExprTree *expr)

{				// Grab the op vector and delete the output expression
  vector<OpTpl *> *res = expr->ops;
  expr->ops = (vector<OpTpl *> *)0;
  delete expr;
  return res;
}

void ExprTree::setOutput(VarnodeTpl *newout)

{				// Force the output of the expression to be new out
				// If the original output is named, this requires
				// an extra COPY op
  OpTpl *op;
  if (outvn == (VarnodeTpl *)0)
    throw SleighError("Expression has no output");
  if (outvn->isUnnamed()) {
    delete outvn;
    op = ops->back();
    op->clearOutput();
    op->setOutput(newout);
  }
  else {
    op = new OpTpl(CPUI_COPY);
    op->addInput(outvn);
    op->setOutput(newout);
    ops->push_back(op);
  }
  outvn = new VarnodeTpl(*newout);
}

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

void PcodeCompile::matchSize(int4 j,OpTpl *op,bool inputonly,const vector<OpTpl *> &ops)

{				// Find something to fill in zero size varnode
				// j is the slot we are trying to fill (-1=output)
				// Don't check output for non-zero if inputonly is true
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

void PcodeCompile::fillinZero(OpTpl *op,const vector<OpTpl *> &ops)

{				// Try to get rid of zero size varnodes in op
  // Right now this is written assuming operands for the constructor are
  // are built before any other pcode in the constructor is generated

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

bool PcodeCompile::propagateSize(ConstructTpl *ct)

{				// Fill in size for varnodes with size 0
				// Return first OpTpl with a size 0 varnode
				// that cannot be filled in or NULL otherwise
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

VarnodeTpl *PcodeCompile::buildTemporary(void)

{				// Build temporary variable (with zerosize)
  VarnodeTpl *res = new VarnodeTpl(ConstTpl(uniqspace),
				   ConstTpl(ConstTpl::real,allocateTemp()),
				   ConstTpl(ConstTpl::real,0));
  res->setUnnamed(true);
  return res;
}

LabelSymbol *PcodeCompile::defineLabel(string *name)

{ // Create a label symbol
  LabelSymbol *labsym = new LabelSymbol(*name,local_labelcount++);
  delete name;
  addSymbol(labsym);		// Add symbol to local scope
  return labsym;
}

vector<OpTpl *> *PcodeCompile::placeLabel(LabelSymbol *labsym)

{ // Create placeholder OpTpl for a label
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

void PcodeCompile::newLocalDefinition(string *varname,uint4 size)

{ // Create a new temporary symbol (without generating any pcode)
  VarnodeSymbol *sym;
  sym = new VarnodeSymbol(*varname,uniqspace,allocateTemp(),size);
  addSymbol(sym);
  delete varname;
}

ExprTree *PcodeCompile::createOp(OpCode opc,ExprTree *vn)

{				// Create new expression with output -outvn-
				// built by performing -opc- on input vn.
				// Free input expression
  VarnodeTpl *outvn = buildTemporary();
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  op->setOutput(outvn);
  vn->ops->push_back(op);
  vn->outvn = new VarnodeTpl(*outvn);
  return vn;
}

ExprTree *PcodeCompile::createOp(OpCode opc,ExprTree *vn1,
				    ExprTree *vn2)

{				// Create new expression with output -outvn-
				// built by performing -opc- on inputs vn1 and vn2.
				// Free input expressions
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

ExprTree *PcodeCompile::createOpOut(VarnodeTpl *outvn,OpCode opc,
				       ExprTree *vn1,ExprTree *vn2)
{ // Create an op with explicit output and two inputs
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

ExprTree *PcodeCompile::createOpOutUnary(VarnodeTpl *outvn,OpCode opc,ExprTree *vn)

{ // Create an op with explicit output and 1 input
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  op->setOutput(outvn);
  vn->ops->push_back(op);
  vn->outvn = new VarnodeTpl(*outvn);
  return vn;
}

vector<OpTpl *> *PcodeCompile::createOpNoOut(OpCode opc,ExprTree *vn)

{				// Create new expression by creating op with given -opc-
				// and single input vn.   Free the input expression
  OpTpl *op = new OpTpl(opc);
  op->addInput(vn->outvn);
  vn->outvn = (VarnodeTpl *)0;	// There is no longer an output to this expression
  vector<OpTpl *> *res = vn->ops;
  vn->ops = (vector<OpTpl *> *)0;
  delete vn;
  res->push_back(op);
  return res;
}

vector<OpTpl *> *PcodeCompile::createOpNoOut(OpCode opc,ExprTree *vn1,ExprTree *vn2)

{				// Create new expression by creating op with given -opc-
				// and inputs vn1 and vn2. Free the input expressions
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

ExprTree *PcodeCompile::createLoad(StarQuality *qual,ExprTree *ptr)

{				// Create new load expression, free ptr expression
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

vector<OpTpl *> *PcodeCompile::createStore(StarQuality *qual,
					      ExprTree *ptr,ExprTree *val)
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

ExprTree *PcodeCompile::createUserOp(UserOpSymbol *sym,vector<ExprTree *> *param)

{ // Create userdefined pcode op, given symbol and parameters
  VarnodeTpl *outvn = buildTemporary();
  ExprTree *res = new ExprTree();
  res->ops = createUserOpNoOut(sym,param);
  res->ops->back()->setOutput(outvn);
  res->outvn = new VarnodeTpl(*outvn);
  return res;
}

vector<OpTpl *> *PcodeCompile::createUserOpNoOut(UserOpSymbol *sym,vector<ExprTree *> *param)

{
  OpTpl *op = new OpTpl(CPUI_CALLOTHER);
  VarnodeTpl *vn = new VarnodeTpl(ConstTpl(constantspace),
				    ConstTpl(ConstTpl::real,sym->getIndex()),
				    ConstTpl(ConstTpl::real,4));
  op->addInput(vn);
  return ExprTree::appendParams(op,param);
}

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

void PcodeCompile::appendOp(OpCode opc,ExprTree *res,uintb constval,int4 constsz)

{ // Take output of res expression, combine with constant,
  // using opc operation, return the resulting expression
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

VarnodeTpl *PcodeCompile::buildTruncatedVarnode(VarnodeTpl *basevn,uint4 bitoffset,uint4 numbits)

{ // Build a truncated form -basevn- that matches the bitrange [ -bitoffset-, -numbits- ] if possible
  // using just ConstTpl mechanics, otherwise return null
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

  if (basevn->getSpace().isUniqueSpace()) // Do we really want to prevent truncated uniques??
    return (VarnodeTpl *)0;

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

vector<OpTpl *> *PcodeCompile::assignBitRange(VarnodeTpl *vn,uint4 bitoffset,uint4 numbits,ExprTree *rhs)

{ // Create an expression assigning the rhs to a bitrange within sym
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

ExprTree *PcodeCompile::createBitRange(SpecificSymbol *sym,uint4 bitoffset,uint4 numbits)

{ // Create an expression computing the indicated bitrange of sym
  // The result is truncated to the smallest byte size that can
  // contain the indicated number of bits. The result has the
  // desired bits shifted all the way to the right
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

VarnodeTpl *PcodeCompile::addressOf(VarnodeTpl *var,uint4 size)

{				// Produce constant varnode that is the offset
				// portion of varnode -var-
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
