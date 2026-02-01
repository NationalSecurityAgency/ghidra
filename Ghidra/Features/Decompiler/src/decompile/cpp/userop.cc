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
#include "userop.hh"
#include "funcdata.hh"

namespace ghidra {

AttributeId ATTRIB_FARPOINTER = AttributeId("farpointer",85);
AttributeId ATTRIB_INPUTOP = AttributeId("inputop",86);
AttributeId ATTRIB_OUTPUTOP = AttributeId("outputop",87);
AttributeId ATTRIB_USEROP = AttributeId("userop",88);

ElementId ELEM_CONSTRESOLVE = ElementId("constresolve",127);
ElementId ELEM_JUMPASSIST = ElementId("jumpassist",128);
ElementId ELEM_SEGMENTOP = ElementId("segmentop",129);

const uint4 UserPcodeOp::BUILTIN_STRINGDATA = 0x10000000;
const uint4 UserPcodeOp::BUILTIN_VOLATILE_READ = 0x10000001;
const uint4 UserPcodeOp::BUILTIN_VOLATILE_WRITE = 0x10000002;
const uint4 UserPcodeOp::BUILTIN_MEMCPY = 0x10000003;
const uint4 UserPcodeOp::BUILTIN_STRNCPY = 0x10000004;
const uint4 UserPcodeOp::BUILTIN_WCSNCPY = 0x10000005;

int4 UserPcodeOp::extractAnnotationSize(const Varnode *vn,const PcodeOp *op)

{
  throw LowlevelError("Unexpected annotation input for CALLOTHER " + name);
}

/// \brief Constructor given specific input/output data-types
///
/// An optional output data-type for the CALLOTHER can be specified and up to 4 input data-types
/// associated with the first 4 inputs to the CALLOTHER (after the userop id in slot 0).
/// \param nm is the name to associate with the user-op
/// \param g is the Architecture owning the new user-op
/// \param ind is the id associated with the user-op
/// \param out is the data-type to associate with the CALLOTHER output (may be null)
/// \param in0 is the first input data-type (may be null)
/// \param in1 is the second input data-type (may be null)
/// \param in2 is the third input data-type (may be null)
/// \param in3 is the fourth input data-type (may be null)
DatatypeUserOp::DatatypeUserOp(const string &nm,Architecture *g,int4 ind,Datatype *out,
			       Datatype *in0,Datatype *in1,Datatype *in2,Datatype *in3)
  : UserPcodeOp(nm,g,datatype,ind)
{
  outType = out;
  if (in0 != (Datatype *)0)
    inTypes.push_back(in0);
  if (in1 != (Datatype *)0)
    inTypes.push_back(in1);
  if (in2 != (Datatype *)0)
    inTypes.push_back(in2);
  if (in3 != (Datatype *)0)
    inTypes.push_back(in3);
}

Datatype *DatatypeUserOp::getOutputLocal(const PcodeOp *op) const

{
  return outType;
}

Datatype *DatatypeUserOp::getInputLocal(const PcodeOp *op,int4 slot) const

{
  slot -= 1;
  if (slot >= 0 && slot < inTypes.size())
    return inTypes[slot];
  return (Datatype *)0;
}

void InjectedUserOp::decode(Decoder &decoder)

{
  injectid = glb->pcodeinjectlib->decodeInject("userop", "", InjectPayload::CALLOTHERFIXUP_TYPE,decoder);
  name = glb->pcodeinjectlib->getCallOtherTarget(injectid);
  UserPcodeOp *base = glb->userops.getOp(name);
  // This tag overrides the base functionality of a userop
  // so the core userop name and index may already be defined
  if (base == (UserPcodeOp *)0)
    throw LowlevelError("Unknown userop name in <callotherfixup>: "+name);
  if (dynamic_cast<UnspecializedPcodeOp *>(base) == (UnspecializedPcodeOp *)0)	// Make sure the userop isn't used for some other purpose
    throw LowlevelError("<callotherfixup> overloads userop with another purpose: "+name);
  useropindex = base->getIndex();	// Get the index from the core userop
}

/// This allows a single user defined operator to have multiple symbol names
/// based on the size of its operands in context.
/// \param base is the string to append the suffix to
/// \param size is the size to encode expressed as the number of bytes
/// \return the appended string
string VolatileOp::appendSize(const string &base,int4 size)

{
  if (size==1)
    return base + "_1";
  if (size==2)
    return base + "_2";
  if (size==4)
    return base + "_4";
  if (size==8)
    return base + "_8";
  ostringstream s;
  s << base << '_' << dec << size;
  return s.str();
}

string VolatileReadOp::getOperatorName(const PcodeOp *op) const

{
  if (op->getOut() == (Varnode *)0) return name;
  return appendSize(name,op->getOut()->getSize());
}

Datatype *VolatileReadOp::getOutputLocal(const PcodeOp *op) const

{
  if (!op->doesSpecialPropagation())
    return (Datatype *)0;
  const Address &addr ( op->getIn(1)->getAddr() ); // Address of volatile memory
  int4 size = op->getOut()->getSize(); // Size of memory being written
  uint4 vflags = 0;
  SymbolEntry *entry = glb->symboltab->getGlobalScope()->queryProperties(addr,size,op->getAddr(),vflags);
  if (entry != (SymbolEntry *)0) {
    return entry->getSizedType(addr,size);
  }
  return (Datatype *)0;
}

int4 VolatileReadOp::extractAnnotationSize(const Varnode *vn,const PcodeOp *op)

{
  const Varnode *outvn = op->getOut();
  if (outvn != (const Varnode *)0)
    return op->getOut()->getSize(); // Get size from output of read function
  return 1;
}

string VolatileWriteOp::getOperatorName(const PcodeOp *op) const

{
  if (op->numInput() < 3) return name;
  return appendSize(name,op->getIn(2)->getSize());
}

Datatype *VolatileWriteOp::getInputLocal(const PcodeOp *op,int4 slot) const

{
  if (!op->doesSpecialPropagation() || slot != 2)
    return (Datatype *)0;
  const Address &addr ( op->getIn(1)->getAddr() ); // Address of volatile memory
  int4 size = op->getIn(2)->getSize(); // Size of memory being written
  uint4 vflags = 0;
  SymbolEntry *entry = glb->symboltab->getGlobalScope()->queryProperties(addr,size,op->getAddr(),vflags);
  if (entry != (SymbolEntry *)0) {
    return entry->getSizedType(addr,size);
  }
  return (Datatype *)0;
}

int4 VolatileWriteOp::extractAnnotationSize(const Varnode *vn,const PcodeOp *op)

{
  return op->getIn(2)->getSize(); // Get size from the 3rd parameter of write function
}

/// \param nm is the low-level name of the segment operation
/// \param g is the owning Architecture for this instance of the segment operation
/// \param ind is the constant id identifying the specific CALLOTHER variant
SegmentOp::SegmentOp(const string &nm,Architecture *g,int4 ind)
  : TermPatternOp(nm,g,segment,ind)
{
  constresolve.space = (AddrSpace *)0;
}

bool SegmentOp::unify(Funcdata &data,PcodeOp *op,
				 vector<Varnode *> &bindlist) const
{
  Varnode *basevn,*innervn;

  // Segmenting is done by a user defined p-code op, so this is what we look for
  // The op must have innervn and basevn (if base is present) as inputs
  // so there isn't much to follow. The OpFollow arrays are no
  // longer needed for unification but are needed to provide
  // a definition for the userop
  if (op->code() != CPUI_CALLOTHER) return false;
  if (op->getIn(0)->getOffset() != useropindex) return false;
  if (op->numInput() != 3) return false;
  innervn = op->getIn(1);
  if (baseinsize != 0) {
    basevn = op->getIn(1);
    innervn = op->getIn(2);
    if (basevn->isConstant())
      basevn = data.newConstant(baseinsize,basevn->getOffset());
    bindlist[0] = basevn;
  }
  else
    bindlist[0] = (Varnode *)0;
  if (innervn->isConstant())
    innervn = data.newConstant(innerinsize,innervn->getOffset());
  bindlist[1] = innervn;
  return true;
}

uintb SegmentOp::execute(const vector<uintb> &input) const

{
  ExecutablePcode *pcodeScript = (ExecutablePcode *)glb->pcodeinjectlib->getPayload(injectId);
  return pcodeScript->evaluate(input);
}

void SegmentOp::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_SEGMENTOP);
  spc = (AddrSpace *)0;
  injectId = -1;
  baseinsize = 0;
  innerinsize = 0;
  supportsfarpointer = false;
  name = "segment"; 		// Default name, might be overridden by userop attribute
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId == ATTRIB_SPACE)
      spc = decoder.readSpace();
    else if (attribId == ATTRIB_FARPOINTER)
      supportsfarpointer = true;
    else if (attribId == ATTRIB_USEROP) {	// Based on existing sleigh op
      name = decoder.readString();
    }
  }
  if (spc == (AddrSpace *)0)
    throw LowlevelError("<segmentop> expecting space attribute");
  UserPcodeOp *otherop = glb->userops.getOp(name);
  if (otherop == (UserPcodeOp *)0)
    throw LowlevelError("<segmentop> unknown userop " + name);
  useropindex = otherop->getIndex();
  if (dynamic_cast<UnspecializedPcodeOp *>(otherop) == (UnspecializedPcodeOp *)0)
    throw LowlevelError("Redefining userop "+name);

  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId==ELEM_CONSTRESOLVE) {
      int4 sz;
      decoder.openElement();
      if (decoder.peekElement() != 0) {
	Address addr = Address::decode(decoder,sz);
	constresolve.space = addr.getSpace();
	constresolve.offset = addr.getOffset();
	constresolve.size = sz;
      }
      decoder.closeElement(subId);
    }
    else if (subId == ELEM_PCODE) {
      string nm = name + "_pcode";
      string source = "cspec";
      injectId = glb->pcodeinjectlib->decodeInject(source, nm, InjectPayload::EXECUTABLEPCODE_TYPE, decoder);
    }
  }
  decoder.closeElement(elemId);
  if (injectId < 0)
    throw LowlevelError("Missing <pcode> child in <segmentop> tag");
  InjectPayload *payload = glb->pcodeinjectlib->getPayload(injectId);
  if (payload->sizeOutput() != 1)
    throw LowlevelError("<pcode> child of <segmentop> tag must declare one <output>");
  if (payload->sizeInput() == 1) {
    innerinsize = payload->getInput(0).getSize();
  }
  else if (payload->sizeInput() == 2) {
    baseinsize = payload->getInput(0).getSize();
    innerinsize = payload->getInput(1).getSize();
  }
  else
    throw LowlevelError("<pcode> child of <segmentop> tag must declare one or two <input> tags");
}

/// \param g is the Architecture owning this set of jump assist scripts
JumpAssistOp::JumpAssistOp(Architecture *g)
  : UserPcodeOp("",g,jumpassist,0)
{
  index2case = -1;
  index2addr = -1;
  defaultaddr = -1;
  calcsize = -1;
}

void JumpAssistOp::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_JUMPASSIST);
  name = decoder.readString(ATTRIB_NAME);
  index2case = -1;	// Mark as not present until we see a tag
  index2addr = -1;
  defaultaddr = -1;
  calcsize = -1;
  for(;;) {
    uint4 subId = decoder.peekElement();
    if (subId == 0) break;
    if (subId == ELEM_CASE_PCODE) {
      if (index2case != -1)
	throw LowlevelError("Too many <case_pcode> tags");
      index2case = glb->pcodeinjectlib->decodeInject("jumpassistop", name+"_index2case",
						     InjectPayload::EXECUTABLEPCODE_TYPE,decoder);
    }
    else if (subId == ELEM_ADDR_PCODE) {
      if (index2addr != -1)
	throw LowlevelError("Too many <addr_pcode> tags");
      index2addr = glb->pcodeinjectlib->decodeInject("jumpassistop", name+"_index2addr",
						     InjectPayload::EXECUTABLEPCODE_TYPE,decoder);
    }
    else if (subId == ELEM_DEFAULT_PCODE) {
      if (defaultaddr != -1)
	throw LowlevelError("Too many <default_pcode> tags");
      defaultaddr = glb->pcodeinjectlib->decodeInject("jumpassistop", name+"_defaultaddr",
						      InjectPayload::EXECUTABLEPCODE_TYPE,decoder);
    }
    else if (subId == ELEM_SIZE_PCODE) {
      if (calcsize != -1)
	throw LowlevelError("Too many <size_pcode> tags");
      calcsize = glb->pcodeinjectlib->decodeInject("jumpassistop", name+"_calcsize",
						   InjectPayload::EXECUTABLEPCODE_TYPE,decoder);
    }
  }
  decoder.closeElement(elemId);

  if (index2addr == -1)
    throw LowlevelError("userop: " + name + " is missing <addr_pcode>");
  if (defaultaddr == -1)
    throw LowlevelError("userop: " + name + " is missing <default_pcode>");
  UserPcodeOp *base = glb->userops.getOp(name);
  // This tag overrides the base functionality of a userop
  // so the core userop name and index may already be defined
  if (base == (UserPcodeOp *)0)
    throw LowlevelError("Unknown userop name in <jumpassist>: "+name);
  if (dynamic_cast<UnspecializedPcodeOp *>(base) == (UnspecializedPcodeOp *)0)	// Make sure the userop isn't used for some other purpose
    throw LowlevelError("<jumpassist> overloads userop with another purpose: "+name);
  useropindex = base->getIndex();	// Get the index from the core userop
}

InternalStringOp::InternalStringOp(Architecture *g)
  : UserPcodeOp("stringdata",g,string_data,BUILTIN_STRINGDATA)
{
  flags |= display_string;
}

Datatype *InternalStringOp::getOutputLocal(const PcodeOp *op) const

{
  return op->getOut()->getType();
}

UserOpManage::UserOpManage(void)

{
  glb = (Architecture *)0;
}

UserOpManage::~UserOpManage(void)

{
  vector<UserPcodeOp *>::iterator iter;

  for(iter=useroplist.begin();iter!=useroplist.end();++iter) {
    UserPcodeOp *userop = *iter;
    if (userop != (UserPcodeOp *)0)
      delete userop;
  }
  map<uint4,UserPcodeOp *>::iterator oiter;
  for(oiter=builtinmap.begin();oiter!=builtinmap.end();++oiter) {
    delete (*oiter).second;
  }
}

/// Every user defined p-code op is initially assigned an UnspecializedPcodeOp description,
/// which may get overridden later.
/// \param g is the Architecture from which to draw user defined operations
void UserOpManage::initialize(Architecture *g)

{
  glb = g;
  vector<string> basicops;
  glb->translate->getUserOpNames(basicops);
  for(uint4 i=0;i<basicops.size();++i) {
    if (basicops[i].size()==0) continue;
    UserPcodeOp *userop = new UnspecializedPcodeOp(basicops[i],glb,i);
    registerOp(userop);
  }
}

/// Retrieve a user-op description object by index
/// \param i is the index
/// \return the indicated user-op description
UserPcodeOp *UserOpManage::getOp(uint4 i) const {
  if (i<useroplist.size())
    return useroplist[i];
  map<uint4,UserPcodeOp *>::const_iterator iter = builtinmap.find(i);
  if (iter == builtinmap.end())
    return (UserPcodeOp *)0;
  return ((*iter).second);
}

/// \param nm is the low-level operation name
/// \return the matching description object or NULL
UserPcodeOp *UserOpManage::getOp(const string &nm) const

{
  map<string,UserPcodeOp *>::const_iterator iter;
  iter = useropmap.find(nm);
  if (iter == useropmap.end()) return (UserPcodeOp *)0;
  return (*iter).second;
}

/// Retrieve a built-in user-op given its id.  If user-op record does not already exist,
/// instantiate a default form of the record.
/// \param i is the index associated
/// \return the matching user-op record
UserPcodeOp *UserOpManage::registerBuiltin(uint4 i)

{
  map<uint4,UserPcodeOp *>::const_iterator iter = builtinmap.find(i);
  if (iter != builtinmap.end())
    return (*iter).second;
  UserPcodeOp *res;
  switch(i) {
    case UserPcodeOp::BUILTIN_STRINGDATA:
      res = new InternalStringOp(glb);
      break;
    case UserPcodeOp::BUILTIN_VOLATILE_READ:
      res = new VolatileReadOp("read_volatile",glb,false);
      break;
    case UserPcodeOp::BUILTIN_VOLATILE_WRITE:
      res = new VolatileWriteOp("write_volatile",glb,false);
      break;
    case UserPcodeOp::BUILTIN_MEMCPY:
    {
      int4 ptrSize = glb->types->getSizeOfPointer();
      int4 wordSize = glb->getDefaultDataSpace()->getWordSize();
      Datatype *vType = glb->types->getTypeVoid();
      Datatype *ptrType = glb->types->getTypePointer(ptrSize,vType,wordSize);
      Datatype *intType = glb->types->getBase(4,TYPE_INT);
      res = new DatatypeUserOp("builtin_memcpy",glb,UserPcodeOp::BUILTIN_MEMCPY,ptrType,ptrType,ptrType,intType);
      break;
    }
    case UserPcodeOp::BUILTIN_STRNCPY:		// Copy "char" elements
    {
      int4 ptrSize = glb->types->getSizeOfPointer();
      int4 wordSize = glb->getDefaultDataSpace()->getWordSize();
      Datatype *cType = glb->types->getTypeChar(glb->types->getSizeOfChar());
      Datatype *ptrType = glb->types->getTypePointer(ptrSize,cType,wordSize);
      Datatype *intType = glb->types->getBase(4,TYPE_INT);
      res = new DatatypeUserOp("builtin_strncpy",glb,UserPcodeOp::BUILTIN_STRNCPY,ptrType,ptrType,ptrType,intType);
      break;
    }
    case UserPcodeOp::BUILTIN_WCSNCPY:		// Copy "wchar_t" elements
    {
      int4 ptrSize = glb->types->getSizeOfPointer();
      int4 wordSize = glb->getDefaultDataSpace()->getWordSize();
      Datatype *cType = glb->types->getTypeChar(glb->types->getSizeOfWChar());
      Datatype *ptrType = glb->types->getTypePointer(ptrSize,cType,wordSize);
      Datatype *intType = glb->types->getBase(4,TYPE_INT);
      res = new DatatypeUserOp("builtin_wcsncpy",glb,UserPcodeOp::BUILTIN_WCSNCPY,ptrType,ptrType,ptrType,intType);
      break;
    }
    default:
      throw LowlevelError("Bad built-in userop id");
  }
  builtinmap[i] = res;
  return res;
}

/// Add the description to the mapping by index and the mapping by name. Make same basic
/// sanity checks for conflicting values and duplicate operations and throw an
/// exception if there's a problem.
/// \param op is the new description object
void UserOpManage::registerOp(UserPcodeOp *op)

{
  int4 ind = op->getIndex();
  if (ind < 0) throw LowlevelError("UserOp not assigned an index");

  map<string,UserPcodeOp *>::iterator iter;
  iter = useropmap.find(op->getName());
  if (iter != useropmap.end()) {
    UserPcodeOp *other = (*iter).second;
    if (other->getIndex() != ind)
      throw LowlevelError("Conflicting indices for userop name "+op->getName());
  }

  while(useroplist.size() <= ind)
    useroplist.push_back((UserPcodeOp *)0);
  if (useroplist[ind] != (UserPcodeOp *)0) {
    if (useroplist[ind]->getName() != op->getName())
      throw LowlevelError("User op "+op->getName()+" has same index as "+useroplist[ind]->getName());
    // We assume this registration customizes an existing userop
    delete useroplist[ind];		// Delete the old spec
  }
  useroplist[ind] = op;		// Index crossref
  useropmap[op->getName()] = op; // Name crossref

  SegmentOp *s_op = dynamic_cast<SegmentOp *>(op);
  if (s_op != (SegmentOp *)0) {
    int4 index = s_op->getSpace()->getIndex();
  
    while(segmentop.size() <= index)
      segmentop.push_back((SegmentOp *)0);
    
    if (segmentop[index] != (SegmentOp *)0)
      throw LowlevelError("Multiple segmentops defined for same space");
    segmentop[index] = s_op;
    return;
  }
}

/// Create a SegmentOp description object based on the element and
/// register it with \b this manager.
/// \param decoder is the stream decoder
/// \param glb is the owning Architecture
void UserOpManage::decodeSegmentOp(Decoder &decoder,Architecture *glb)

{
  SegmentOp *s_op;
  s_op = new SegmentOp("",glb,useroplist.size());
  try {
    s_op->decode(decoder);
    registerOp(s_op);
  } catch(LowlevelError &err) {
    delete s_op;
    throw err;
  }
}

/// Create either a VolatileReadOp or VolatileWriteOp description object based on
/// the element and register it with \b this manager.
/// \param decoder is the stream decoder
/// \param glb is the owning Architecture
void UserOpManage::decodeVolatile(Decoder &decoder,Architecture *glb)

{
  string readOpName;
  string writeOpName;
  bool functionalDisplay = false;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0) break;
    if (attribId==ATTRIB_INPUTOP) {
      readOpName = decoder.readString();
    }
    else if (attribId==ATTRIB_OUTPUTOP) {
      writeOpName = decoder.readString();
    }
    else if (attribId == ATTRIB_FORMAT) {
      string format = decoder.readString();
      if (format == "functional")
	functionalDisplay = true;
    }
  }
  if (readOpName.size() == 0 || writeOpName.size() == 0)
    throw LowlevelError("Missing inputop/outputop attributes in <volatile> element");
  map<uint4,UserPcodeOp *>::const_iterator iter;
  if (builtinmap.find(UserPcodeOp::BUILTIN_VOLATILE_READ) != builtinmap.end())
    throw LowlevelError("read_volatile user-op registered more than once");
  if (builtinmap.find(UserPcodeOp::BUILTIN_VOLATILE_WRITE) != builtinmap.end())
    throw LowlevelError("write_volatile user-op registered more than once");
  VolatileReadOp *vr_op = new VolatileReadOp(readOpName,glb,functionalDisplay);
  builtinmap[UserPcodeOp::BUILTIN_VOLATILE_READ] = vr_op;
  VolatileWriteOp *vw_op = new VolatileWriteOp(writeOpName,glb,functionalDisplay);
  builtinmap[UserPcodeOp::BUILTIN_VOLATILE_WRITE] = vw_op;
}

/// Create an InjectedUserOp description object based on the element
/// and register it with \b this manager.
/// \param decoder is the stream decoder
/// \param glb is the owning Architecture
void UserOpManage::decodeCallOtherFixup(Decoder &decoder,Architecture *glb)

{
  InjectedUserOp *op = new InjectedUserOp("",glb,0,0);
  try {
    op->decode(decoder);
    registerOp(op);
  } catch(LowlevelError &err) {
    delete op;
    throw err;
  }
}

/// Create a JumpAssistOp description object based on the element
/// and register it with \b this manager.
/// \param decoder is the stream decoder
/// \param glb is the owning Architecture
void UserOpManage::decodeJumpAssist(Decoder &decoder,Architecture *glb)

{
  JumpAssistOp *op = new JumpAssistOp(glb);
  try {
    op->decode(decoder);
    registerOp(op);
  } catch(LowlevelError &err) {
    delete op;
    throw err;
  }
}

/// \brief Manually install an InjectedUserOp given just names of the user defined op and the p-code snippet
///
/// An alternate way to attach a call-fixup to user defined p-code ops, without using XML. The
/// p-code to inject is presented as a raw string to be handed to the p-code parser.
/// \param useropname is the name of the user defined op
/// \param outname is the name of the output variable in the snippet
/// \param inname is the list of input variable names in the snippet
/// \param snippet is the raw p-code source snippet
/// \param glb is the owning Architecture
void UserOpManage::manualCallOtherFixup(const string &useropname,const string &outname,
					const vector<string> &inname,const string &snippet,Architecture *glb)

{
  UserPcodeOp *userop = getOp(useropname);
  if (userop == (UserPcodeOp *)0)
    throw LowlevelError("Unknown userop: "+useropname);
  if (dynamic_cast<UnspecializedPcodeOp *>(userop) == (UnspecializedPcodeOp *)0)
    throw LowlevelError("Cannot fixup userop: "+useropname);

  int4 injectid = glb->pcodeinjectlib->manualCallOtherFixup(useropname,outname,inname,snippet);
  InjectedUserOp *op = new InjectedUserOp(useropname,glb,userop->getIndex(),injectid);
  try {
    registerOp(op);
  } catch(LowlevelError &err) {
    delete op;
    throw err;
  }
}

} // End namespace ghidra
