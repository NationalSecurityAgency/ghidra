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
#include "override.hh"
#include "funcdata.hh"

namespace ghidra {

ElementId ELEM_DEADCODEDELAY = ElementId("deadcodedelay",218);
ElementId ELEM_FLOW = ElementId("flow",219);
ElementId ELEM_FORCEGOTO = ElementId("forcegoto",220);
ElementId ELEM_CALLDEST = ElementId("calldest",221);
ElementId ELEM_MULTISTAGEJUMP = ElementId("multistagejump",222);
ElementId ELEM_OVERRIDE = ElementId("override",223);
ElementId ELEM_PROTOOVERRIDE = ElementId("protooverride",224);

ValueDomainConstraint::ValueDomainConstraint(const Address &owner,const Address &load,int4 size,
    const Address &use,uintb lo,uintb hi,const Address &descriptor,const string &source,
    const Address &guard,bool trueEdge)
  : ValueDomainConstraint(owner,load,size,use,lo,hi,descriptor,source,guard,trueEdge,true)
{
}

ValueDomainConstraint::ValueDomainConstraint(const Address &owner,const Address &load,int4 size,
    uintb lo,uintb hi,const Address &descriptor,const string &source,const Address &guard,bool trueEdge)
  : ValueDomainConstraint(owner,load,size,Address((AddrSpace *)0,0),lo,hi,descriptor,source,guard,trueEdge,false)
{
}

ValueDomainConstraint::ValueDomainConstraint(const Address &owner,const Address &load,int4 size,
    const Address &use,uintb lo,uintb hi,const Address &descriptor,const string &source,
    const Address &guard,bool trueEdge,bool useRestricted)
  : ownerEntry(owner), loadAddress(load), outputSize(size),
    switchAddress(useRestricted && !use.isInvalid() ? use : Address((AddrSpace *)0,0)), first(lo), last(hi),
    descriptorAddress(descriptor), provenance(source),
    guardAddress(guard.isInvalid() ? Address((AddrSpace *)0,0) : guard),
    guardTrue(!guard.isInvalid() && trueEdge)
{
  if (owner.isInvalid() || load.isInvalid() || descriptor.isInvalid() ||
      (useRestricted && use.isInvalid()) ||
      owner.getSpace()->getType() != IPTR_PROCESSOR || load.getSpace()->getType() != IPTR_PROCESSOR ||
      (useRestricted && use.getSpace()->getType() != IPTR_PROCESSOR) ||
      descriptor.getSpace()->getType() != IPTR_PROCESSOR ||
      (!guard.isInvalid() && guard.getSpace()->getType() != IPTR_PROCESSOR))
    throw LowlevelError("Value-domain addresses must be memory addresses");
  if (size < 1 || size > 8)
    throw LowlevelError("Value-domain width must be 1 through 8 bytes");
  uintb maximum = size == 8 ? ~(uintb)0 : (((uintb)1 << (8 * size)) - 1);
  if (lo > hi || hi > maximum)
    throw LowlevelError("Value-domain bounds do not fit the unsigned width");
  if (source.find_first_not_of(" \t\r\n\f\v") == string::npos)
    throw LowlevelError("Value-domain provenance is required");
}

bool ValueDomainConstraint::hasSameSelector(const ValueDomainConstraint &other) const

{
  return ownerEntry == other.ownerEntry && loadAddress == other.loadAddress &&
      outputSize == other.outputSize && (!isUseRestricted() || !other.isUseRestricted() ||
      switchAddress == other.switchAddress);
}

static void encodeDomainAddress(Encoder &encoder,const char *role,const Address &addr)

{
  encoder.openElement(ELEM_ADDR);
  encoder.writeString(ATTRIB_TYPE,role);
  if (!addr.isInvalid()) {
    encoder.writeSpace(ATTRIB_SPACE,addr.getSpace());
    encoder.writeUnsignedInteger(ATTRIB_OFFSET,addr.getOffset());
  }
  encoder.closeElement(ELEM_ADDR);
}

void ValueDomainConstraint::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_VALUEDOMAIN);
  encoder.writeSignedInteger(ATTRIB_FORMAT,1);
  encoder.writeString(ATTRIB_TYPE,"load");
  encoder.writeSignedInteger(ATTRIB_SIZE,outputSize);
  encoder.writeUnsignedInteger(ATTRIB_FIRST,first);
  encoder.writeUnsignedInteger(ATTRIB_LAST,last);
  encoder.writeString(ATTRIB_NAME,provenance);
  encoder.writeSignedInteger(ATTRIB_INDEX,guardAddress.isInvalid() ? -1 : guardTrue ? 1 : 0);
  encodeDomainAddress(encoder,"owner",ownerEntry);
  encodeDomainAddress(encoder,"load",loadAddress);
  encodeDomainAddress(encoder,"switch",switchAddress);
  encodeDomainAddress(encoder,"descriptor",descriptorAddress);
  if (!guardAddress.isInvalid())
    encodeDomainAddress(encoder,"guard",guardAddress);
  encoder.closeElement(ELEM_VALUEDOMAIN);
}

static Address decodeDomainAddress(Decoder &decoder,const char *expectedRole)

{
  uint4 element = decoder.openElement(ELEM_ADDR);
  int4 fields = 0;
  string role;
  AddrSpace *space = (AddrSpace *)0;
  uintb offset = 0;
  for(uint4 id;(id = decoder.getNextAttributeId()) != 0;) {
    int4 bit;
    if (id == ATTRIB_TYPE) { bit = 1; role = decoder.readString(); }
    else if (id == ATTRIB_SPACE) { bit = 2; space = decoder.readSpace(); }
    else if (id == ATTRIB_OFFSET) { bit = 4; offset = decoder.readUnsignedInteger(); }
    else { throw DecoderError("Unknown value-domain address attribute"); }
    if ((fields & bit) != 0)
      throw DecoderError("Duplicate value-domain address attribute");
    fields |= bit;
  }
  if (fields == 1 && string(expectedRole) == "switch" && role == expectedRole) {
    decoder.closeElement(element);
    return Address((AddrSpace *)0,0);
  }
  if (fields != 7 || role != expectedRole || space == (AddrSpace *)0)
    throw DecoderError("Unexpected value-domain address role");
  decoder.closeElement(element);
  if (offset > space->getHighest())
    throw DecoderError("Value-domain address offset exceeds its address space");
  return Address(space,offset);
}

/// The caller has already opened the valuedomain element and closes it after this returns.
ValueDomainConstraint ValueDomainConstraint::decodeFromElement(Decoder &decoder)

{
  int4 fields = 0;
  int8 format = -1, size = 0, edge = -2;
  uintb first = 0, last = 0;
  string type, source;
  for(uint4 id;(id = decoder.getNextAttributeId()) != 0;) {
    int4 bit;
    if (id == ATTRIB_FORMAT) { bit = 1; format = decoder.readSignedInteger(); }
    else if (id == ATTRIB_TYPE) { bit = 2; type = decoder.readString(); }
    else if (id == ATTRIB_SIZE) { bit = 4; size = decoder.readSignedInteger(); }
    else if (id == ATTRIB_FIRST) { bit = 8; first = decoder.readUnsignedInteger(); }
    else if (id == ATTRIB_LAST) { bit = 16; last = decoder.readUnsignedInteger(); }
    else if (id == ATTRIB_NAME) { bit = 32; source = decoder.readString(); }
    else if (id == ATTRIB_INDEX) { bit = 64; edge = decoder.readSignedInteger(); }
    else { throw DecoderError("Unknown value-domain attribute"); }
    if ((fields & bit) != 0)
      throw DecoderError("Duplicate value-domain attribute");
    fields |= bit;
  }
  if (fields != 127 || format != 1 || type != "load" || size < 1 || size > 8 || edge < -1 || edge > 1)
    throw DecoderError("Unsupported value-domain schema");
  Address owner = decodeDomainAddress(decoder,"owner");
  Address load = decodeDomainAddress(decoder,"load");
  Address use = decodeDomainAddress(decoder,"switch");
  Address descriptor = decodeDomainAddress(decoder,"descriptor");
  Address guard = edge == -1 ? Address((AddrSpace *)0,0) : decodeDomainAddress(decoder,"guard");
  if (decoder.peekElement() != 0)
    throw DecoderError("Unexpected value-domain child");
  if (use.isInvalid())
    return ValueDomainConstraint(owner,load,(int4)size,first,last,descriptor,source,guard,edge == 1);
  return ValueDomainConstraint(owner,load,(int4)size,use,first,last,descriptor,source,guard,edge == 1);
}

void Override::insertValueDomainConstraint(const ValueDomainConstraint &constraint)

{
  for(vector<ValueDomainConstraint>::const_iterator iter=valueDomains.begin();iter!=valueDomains.end();++iter) {
    if (constraint.hasSameSelector(*iter))
      throw LowlevelError("Duplicate value-domain result/use selector");
  }
  valueDomains.push_back(constraint);
}

void Override::clear(void)

{
  for(map<Address,FuncProto *>::iterator iter=protoover.begin();iter!=protoover.end();++iter)
    delete (*iter).second;

  for(map<Address,Record *>::iterator iter=pcodeover.begin();iter!=pcodeover.end();++iter)
    delete (*iter).second;

  protoover.clear();
  pcodeover.clear();
  forcegoto.clear();
  deadcodedelay.clear();
  deindirect.clear();
  protoover.clear();
  multistagejump.clear();
  valueDomains.clear();
}

/// \brief Generate \e warning message related to a dead code delay
///
/// This is triggered by the insertDeadcodeDelay() command on a specific address space
/// \param index is the index of the address space
/// \param glb is the Architecture object
/// \return the generated message
string Override::generateDeadcodeDelayMessage(int4 index,Architecture *glb)

{
  AddrSpace *spc = glb->getSpace(index);
  string res = "Restarted to delay deadcode elimination for space: " + spc->getName();
  return res;
}

/// \brief Force a specific branch instruction to be an unstructured \e goto
///
/// The command is specified as the address of the branch instruction and
/// the destination address of the branch.  The decompiler will automatically
/// mark this as a \e unstructured, when trying to structure the control-flow
/// \param targetpc is the address of the branch instruction
/// \param destpc is the destination address of the branch
void Override::insertForceGoto(const Address &targetpc,const Address &destpc)

{
  forcegoto[targetpc] = destpc;
}

/// \brief Override the number of passes that are executed before \e dead-code elimination starts
///
/// Every address space has an assigned \e delay (which may be zero) before a PcodeOp
/// involving a Varnode in that address space can be eliminated. This command allows the
/// delay for a specific address space to be increased so that new Varnode accesses can be discovered.
/// \param spc is the address space to modify
/// \param delay is the size of the delay (in passes)
void Override::insertDeadcodeDelay(AddrSpace *spc,int4 delay)

{
  while(deadcodedelay.size() <= spc->getIndex())
    deadcodedelay.push_back(-1);

  deadcodedelay[spc->getIndex()] = delay;
}

/// \brief Check if a delay override is already installed for an address space
///
/// \param spc is the address space
/// \return \b true if an override has already been installed
bool Override::hasDeadcodeDelay(AddrSpace *spc) const

{
  int4 index = spc->getIndex();
  if (index >= deadcodedelay.size())
    return false;
  int4 val = deadcodedelay[index];
  if (val == -1) return false;
  return (val != spc->getDeadcodeDelay());
}

/// \brief Override an indirect call turning it into a direct call
///
/// The command consists of the address of the indirect call instruction and
/// the target address of the direct address
/// \param callPoint is the address of the indirect call
/// \param directAddr is the target address of the direct call
void Override::insertDeindirect(const Address &callPoint,const Address &directAddr)

{
  deindirect[callPoint] = directAddr;
}

/// \brief Override the assumed function prototype at a specific call site
///
/// The exact input and output storage locations are overridden for a
/// specific call instruction (direct or indirect).
/// \param callpoint is the address of the call instruction
/// \param p is the overriding function prototype
void Override::insertProtoOverride(const Address &callpoint,FuncProto *p)

{
  map<Address,FuncProto *>::iterator iter;

  iter = protoover.find(callpoint);
  if (iter != protoover.end())	// Check for pre-existing override
    delete (*iter).second;	// and delete it

  p->setOverride(true);		// Mark this as an override
  protoover[callpoint] = p;	// Take ownership of the object
}

/// \brief Flag an indirect jump for multistage analysis
///
/// \param addr is the address of the indirect jump
void Override::insertMultistageJump(const Address &addr)

{
  multistagejump.push_back(addr);
}

/// \brief Mark a branch instruction with a different flow type
///
/// Change the interpretation of a BRANCH, CALL, or RETURN
/// \param addr is the address of the branch instruction
/// \param type is the type of flow that should be forced
void Override::insertFlowOverride(const Address &addr,const string &type)

{
  Record *rec = Record::allocateFlow(type);
  pcodeover[addr] = rec;
}

/// \brief Change a CALL, CALLIND, or CALLOTHER instruction into a CALL with the specified destination address
///
/// \param addr is the address of the instruction
/// \param dest is the new destination address
/// \param type is the type of override to force
void Override::insertDestinationOverride(const Address &addr,const Address &dest,const string &type)

{
  Record *rec = Record::allocateCallDest(type,dest);
  pcodeover[addr] = rec;
}

/// \brief Look for and apply a function prototype override
///
/// Given a call point, look for a prototype override and copy
/// the call specification in
/// \param data is the (calling) function
/// \param fspecs is a reference to the call specification
void Override::applyPrototype(Funcdata &data,FuncCallSpecs &fspecs) const

{
  if (!protoover.empty()) {
    map<Address,FuncProto *>::const_iterator iter = protoover.find(fspecs.getOp()->getAddr());
    if (iter != protoover.end()) {
      fspecs.copy(*(*iter).second);
    }
  }
}

/// \brief Look for and apply destination overrides of indirect calls
///
/// Given an indirect call, look for any overrides, then copy in
/// the overriding target address of the direct call
/// \param data is (calling) function
/// \param fspecs is a reference to the call specification
void Override::applyIndirect(Funcdata &data,FuncCallSpecs &fspecs) const

{
  if (!deindirect.empty()) {
    map<Address,Address>::const_iterator iter = deindirect.find(fspecs.getOp()->getAddr());
    if (iter != deindirect.end())
      fspecs.setAddress( (*iter).second );
  }
}

/// \brief Check for a multistage marker for a specific indirect jump
///
/// Given the address of an indirect jump, look for the multistate command
/// \param addr is the address of the indirect jump
bool Override::queryMultistageJumptable(const Address &addr) const

{
  for(int4 i=0;i<multistagejump.size();++i) {
    if (multistagejump[i] == addr)
      return true;
  }
  return false;
}

/// \brief Push all the force-goto overrides into the function
///
/// \param data is the function
void Override::applyForceGoto(Funcdata &data) const

{
  map<Address,Address>::const_iterator iter;

  for(iter=forcegoto.begin();iter!=forcegoto.end();++iter)
    data.forceGoto((*iter).first,(*iter).second);
}

/// \brief Apply any dead-code delay overrides
///
/// Look for delays of each address space and apply them to the Heritage object
/// \param data is the function
void Override::applyDeadCodeDelay(Funcdata &data) const

{
  Architecture *glb = data.getArch();
  for(int4 i=0;i<deadcodedelay.size();++i) {
    int4 delay = deadcodedelay[i];
    if (delay < 0) continue;
    AddrSpace *spc = glb->getSpace(i);
    data.setDeadCodeDelay(spc,delay);
  }
}

/// \brief Return the particular flow override at a given address
///
/// \param addr is the address of a branch instruction
/// \return the override record or null if there is no override
const Override::Record *Override::getPCodeOverride(const Address &addr) const

{
  map<Address,Record *>::const_iterator iter;
  iter = pcodeover.find(addr);
  if (iter == pcodeover.end())
    return (Record *)0;
  return (*iter).second;
}

/// \brief Dump a description of the overrides to stream
///
/// Give a description of each override, one per line, that is suitable for debug
/// \param s is the output stream
/// \param glb is the Architecture
void Override::printRaw(ostream &s,Architecture *glb) const

{
  for(map<Address,Address>::const_iterator iter=forcegoto.begin();iter!=forcegoto.end();++iter)
    s << "force goto at " << (*iter).first << " jumping to " << (*iter).second << endl;

  for(int4 i=0;i<deadcodedelay.size();++i) {
    if (deadcodedelay[i] < 0) continue;
    AddrSpace *spc = glb->getSpace(i);
    s << "dead code delay on " << spc->getName() << " set to " << dec << deadcodedelay[i] << endl;
  }

  for(map<Address,Address>::const_iterator iter=deindirect.begin();iter!=deindirect.end();++iter)
    s << "override indirect at " << (*iter).first << " to call directly to " << (*iter).second << endl;

  for(map<Address,Record *>::const_iterator iter=pcodeover.begin();iter!=pcodeover.end();++iter)
    (*iter).second->printRaw(s, (*iter).first);

  for(map<Address,FuncProto *>::const_iterator fiter=protoover.begin();fiter!=protoover.end();++fiter) {
    s << "override prototype at " << (*fiter).first << " to ";
    (*fiter).second->printRaw("func",s);
    s << endl;
  }
}

/// \brief Create warning messages that describe current overrides
///
/// Message are designed to be displayed in the function header comment
/// \param messagelist will hold the generated list of messages
/// \param glb is the Architecture
void Override::generateOverrideMessages(vector<string> &messagelist,Architecture *glb) const

{
  // Generate deadcode delay messages
  for(int4 i=0;i<deadcodedelay.size();++i) {
    if (deadcodedelay[i] >= 0)
      messagelist.push_back( generateDeadcodeDelayMessage(i,glb));
  }
}

/// \brief Encode the override commands to a stream
///
/// All the commands are written as children of a root \<override> element.
/// \param encoder is the stream encoder
/// \param glb is the Architecture
void Override::encode(Encoder &encoder,Architecture *glb) const

{
  if (forcegoto.empty() && deadcodedelay.empty() && deindirect.empty() && protoover.empty() &&
      multistagejump.empty() && pcodeover.empty() && valueDomains.empty())
    return;
  encoder.openElement(ELEM_OVERRIDE);

  for(map<Address,Address>::const_iterator iter=forcegoto.begin();iter!=forcegoto.end();++iter) {
    encoder.openElement(ELEM_FORCEGOTO);
    (*iter).first.encode(encoder);
    (*iter).second.encode(encoder);
    encoder.closeElement(ELEM_FORCEGOTO);
  }

  for(int4 i=0;i<deadcodedelay.size();++i) {
    if (deadcodedelay[i] < 0) continue;
    AddrSpace *spc = glb->getSpace(i);
    encoder.openElement(ELEM_DEADCODEDELAY);
    encoder.writeSpace(ATTRIB_SPACE, spc);
    encoder.writeSignedInteger(ATTRIB_DELAY, deadcodedelay[i]);
    encoder.closeElement(ELEM_DEADCODEDELAY);
  }

  for(map<Address,FuncProto *>::const_iterator fiter=protoover.begin();fiter!=protoover.end();++fiter) {
    encoder.openElement(ELEM_PROTOOVERRIDE);
    (*fiter).first.encode(encoder);
    (*fiter).second->encode(encoder);
    encoder.closeElement(ELEM_PROTOOVERRIDE);
  }

  for(int4 i=0;i<multistagejump.size();++i) {
    encoder.openElement(ELEM_MULTISTAGEJUMP);
    multistagejump[i].encode(encoder);
    encoder.closeElement(ELEM_MULTISTAGEJUMP);
  }

  for(map<Address,Record *>::const_iterator titer=pcodeover.begin();titer!=pcodeover.end();++titer)
    (*titer).second->encode(encoder, (*titer).first);

  for(vector<ValueDomainConstraint>::const_iterator iter=valueDomains.begin();iter!=valueDomains.end();++iter)
    iter->encode(encoder);

  encoder.closeElement(ELEM_OVERRIDE);
}

/// \brief Parse and \<override> element containing override commands
///
/// \param decoder is the stream decoder
/// \param glb is the Architecture
void Override::decode(Decoder &decoder,Architecture *glb)

{
  uint4 elemId = decoder.openElement(ELEM_OVERRIDE);
  for(;;) {
    uint4 subId = decoder.openElement();
    if (subId == 0) break;
    if (subId == ELEM_VALUEDOMAIN) {
      insertValueDomainConstraint(ValueDomainConstraint::decodeFromElement(decoder));
    }
    else if (subId == ELEM_PROTOOVERRIDE) {
      Address callpoint = Address::decode(decoder);
      unique_ptr<FuncProto> fp(new FuncProto());
      fp->setInternal(glb->defaultfp,glb->types->getTypeVoid());
      fp->decode(decoder,glb);
      insertProtoOverride(callpoint,fp.release());
    }
    else if (subId == ELEM_FORCEGOTO) {
      Address targetpc = Address::decode(decoder);
      Address destpc = Address::decode(decoder);
      insertForceGoto(targetpc,destpc);
    }
    else if (subId == ELEM_DEADCODEDELAY) {
      int4 delay = decoder.readSignedInteger(ATTRIB_DELAY);
      AddrSpace *spc = decoder.readSpace(ATTRIB_SPACE);
      if (delay < 0)
	throw LowlevelError("Bad deadcodedelay tag");
      insertDeadcodeDelay(spc,delay);
    }
    else if (subId == ELEM_MULTISTAGEJUMP) {
      Address callpoint = Address::decode(decoder);
      insertMultistageJump(callpoint);
    }
    else if (subId == ELEM_FLOW) {
      string type = decoder.readString(ATTRIB_TYPE);
      Address addr = Address::decode(decoder);
      if (addr.isInvalid())
	throw LowlevelError("Bad flow override address");
      pcodeover[addr] = Record::allocateFlow(type);
    }
    else if (subId == ELEM_CALLDEST) {
      string type = decoder.readString(ATTRIB_TYPE);
      Address addr = Address::decode(decoder);
      Address dest = Address::decode(decoder);
      if (addr.isInvalid() || dest.isInvalid())
	throw LowlevelError("Bad destination override address");
      pcodeover[addr] = Record::allocateCallDest(type,dest);
    }
    decoder.closeElement(subId);
  }
  decoder.closeElement(elemId);
}

/// Flow records take no additional parameters to construct
/// \param name is the particular flow override name
/// \return a newly allocated flow override record
Override::Record *Override::Record::allocateFlow(const string &name)

{
  if (name == Branch::NAME)
    return new Branch();
  else if (name == Call::NAME)
    return new Call();
  else if (name == CallReturn::NAME)
    return new CallReturn();
  else if (name == Return::NAME)
    return new Return();
  throw LowlevelError("Unknown flow override name: "+name);
}

/// \param name is the particular call destination override name
/// \param dest is the new destination address
/// \return a newly allocated destination override record
Override::Record *Override::Record::allocateCallDest(const string &name,const Address &dest)

{
  if (name == CallotherCall::NAME)
    return new CallotherCall(dest);
  else if (name == CallotherBranch::NAME)
    return new CallotherBranch(dest);
  else if (name == CallCall::NAME)
    return new CallCall(dest);
  throw LowlevelError("Unknown call destination override name: "+name);
}

const string Override::Branch::NAME = "branch";

void Override::Branch::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,false,true,false,true);

  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply BRANCH override");
  OpCode opc = op->code();
  if (opc == CPUI_CALL)
    data.opSetOpcode(op,CPUI_BRANCH);
  else if (opc == CPUI_CALLIND)
    data.opSetOpcode(op,CPUI_BRANCHIND);
  else if (opc == CPUI_RETURN)
    data.opSetOpcode(op,CPUI_BRANCHIND);
}

void Override::Branch::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_FLOW);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  encoder.closeElement(ELEM_FLOW);
}

void Override::Branch::printRaw(ostream &s,const Address &addr) const

{
  s << "override CALL, CALLIND, or RETURN at " << addr << " to a BRANCH" << endl;
}

const string Override::Call::NAME = "call";

void Override::Call::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,true,false,false,true);

  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply CALL override");
  OpCode opc = op->code();
  if (opc == CPUI_BRANCH)
    data.opSetOpcode(op,CPUI_CALL);
  else if (opc == CPUI_BRANCHIND)
    data.opSetOpcode(op,CPUI_CALLIND);
  else if (opc == CPUI_CBRANCH)
    throw LowlevelError("Do not currently support CBRANCH overrides");
  else if (opc == CPUI_RETURN)
    data.opSetOpcode(op,CPUI_CALLIND);
}

void Override::Call::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_FLOW);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  encoder.closeElement(ELEM_FLOW);
}

void Override::Call::printRaw(ostream &s,const Address &addr) const

{
  s << "override BRANCH, BRANCHIND, or RETURN at " << addr << " to a CALL" << endl;
}

const string Override::CallReturn::NAME = "callreturn";

void Override::CallReturn::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,true,true,false,true);

  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply CALL_RETURN override");
  OpCode opc = op->code();
  if (opc == CPUI_BRANCH)
    data.opSetOpcode(op,CPUI_CALL);
  else if (opc == CPUI_BRANCHIND)
    data.opSetOpcode(op,CPUI_CALLIND);
  else if (opc == CPUI_CBRANCH)
    throw LowlevelError("Do not currently support CBRANCH overrides");
  else if (opc == CPUI_RETURN)
    data.opSetOpcode(op,CPUI_CALLIND);
  PcodeOp *newReturn = data.newOp(1,addr);
  data.opSetOpcode(newReturn,CPUI_RETURN);
  data.opSetInput(newReturn,data.newConstant(1,0),0);
  data.opDeadInsertAfter(newReturn,op);
}

void Override::CallReturn::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_FLOW);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  encoder.closeElement(ELEM_FLOW);
}

void Override::CallReturn::printRaw(ostream &s,const Address &addr) const

{
  s << "override BRANCH, BRANCHIND, or RETURN at " << addr << " to a CALL followed by a RETURN" << endl;
}

const string Override::Return::NAME = "return";

void Override::Return::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,true,true,false,false);
  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply RETURN override");
  OpCode opc = op->code();
  if (opc == CPUI_BRANCH || opc == CPUI_CBRANCH || opc == CPUI_CALL)
    throw LowlevelError("Do not currently support complex overrides");
  else if (opc == CPUI_BRANCHIND)
    data.opSetOpcode(op,CPUI_RETURN);
  else if (opc == CPUI_CALLIND)
    data.opSetOpcode(op,CPUI_RETURN);
}

void Override::Return::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_FLOW);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  encoder.closeElement(ELEM_FLOW);
}

void Override::Return::printRaw(ostream &s,const Address &addr) const

{
  s << "override BRANCHIND or CALLIND at " << addr << " to a RETURN" << endl;
}

const string Override::CallotherCall::NAME = "callother_call";

void Override::CallotherCall::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,false,false,true,false);
  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply CALLOTHER->CALL override");
  data.opSetOpcode(op,CPUI_CALL);
  data.opSetInput(op, data.newCodeRef(callAddress), 0);
}

void Override::CallotherCall::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_CALLDEST);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  callAddress.encode(encoder);
  encoder.closeElement(ELEM_CALLDEST);
}

void Override::CallotherCall::printRaw(ostream &s,const Address &addr) const

{
  s << "override CALLOTHER at " << addr << " to CALL directly to " << callAddress << endl;
}

const string Override::CallotherBranch::NAME = "callother_branch";

void Override::CallotherBranch::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,false,false,true,false);
  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply CALLOTHER->BRANCH override");
  data.opSetOpcode(op,CPUI_BRANCH);
  data.opSetInput(op, data.newCodeRef(branchAddress), 0);
}

void Override::CallotherBranch::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_CALLDEST);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  branchAddress.encode(encoder);
  encoder.closeElement(ELEM_CALLDEST);
}

void Override::CallotherBranch::printRaw(ostream &s,const Address &addr) const

{
  s << "override CALLOTHER at " << addr << " to BRANCH directly to " << branchAddress << endl;
}

const string Override::CallCall::NAME = "call_call";

void Override::CallCall::performOverride(const Address &addr,Funcdata &data) const

{
  PcodeOp *op = data.findPrimaryBranch(addr,false,true,false,false);
  if (op == (PcodeOp *)0 || !op->isDead())
    throw LowlevelError("Could not apply CALL destination override");
  data.opSetOpcode(op, CPUI_CALL);
  data.opSetInput(op, data.newCodeRef(callAddress), 0);
}

void Override::CallCall::encode(Encoder &encoder,const Address &addr) const

{
  encoder.openElement(ELEM_CALLDEST);
  encoder.writeString(ATTRIB_TYPE, NAME);
  addr.encode(encoder);
  callAddress.encode(encoder);
  encoder.closeElement(ELEM_CALLDEST);
}

void Override::CallCall::printRaw(ostream &s,const Address &addr) const

{
  s << "override CALL at " << addr << " to call to a new address " << callAddress << endl;
}

} // End namespace ghidra
