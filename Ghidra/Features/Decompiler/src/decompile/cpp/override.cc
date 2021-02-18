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

void Override::clear(void)

{
  map<Address,FuncProto *>::iterator iter;

  for(iter=protoover.begin();iter!=protoover.end();++iter)
    delete (*iter).second;

  forcegoto.clear();
  deadcodedelay.clear();
  indirectover.clear();
  protoover.clear();
  multistagejump.clear();
  flowoverride.clear();
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
/// \param callpoint is the address of the indirect call
/// \param directcall is the target address of the direct call
void Override::insertIndirectOverride(const Address &callpoint,const Address &directcall)

{
  indirectover[callpoint] = directcall;
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
void Override::insertFlowOverride(const Address &addr,uint4 type)

{
  flowoverride[addr] = type;
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
  if (!indirectover.empty()) {
    map<Address,Address>::const_iterator iter = indirectover.find(fspecs.getOp()->getAddr());
    if (iter != indirectover.end())
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
/// \return the override type
uint4 Override::getFlowOverride(const Address &addr) const

{
  map<Address,uint4>::const_iterator iter;
  iter = flowoverride.find(addr);
  if (iter == flowoverride.end())
    return Override::NONE;
  return (*iter).second;
}

/// \brief Dump a description of the overrides to stream
///
/// Give a description of each override, one per line, that is suitable for debug
/// \param s is the output stream
/// \param glb is the Architecture
void Override::printRaw(ostream &s,Architecture *glb) const

{
  map<Address,Address>::const_iterator iter;

  for(iter=forcegoto.begin();iter!=forcegoto.end();++iter)
    s << "force goto at " << (*iter).first << " jumping to " << (*iter).second << endl;

  for(int4 i=0;i<deadcodedelay.size();++i) {
    if (deadcodedelay[i] < 0) continue;
    AddrSpace *spc = glb->getSpace(i);
    s << "dead code delay on " << spc->getName() << " set to " << dec << deadcodedelay[i] << endl;
  }

  for(iter=indirectover.begin();iter!=indirectover.end();++iter)
    s << "override indirect at " << (*iter).first << " to call directly to " << (*iter).second << endl;

  map<Address,FuncProto *>::const_iterator fiter;

  for(fiter=protoover.begin();fiter!=protoover.end();++fiter) {
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

/// \brief Write the override commands to an XML stream
///
/// All the commands are written as sub-tags of a root \<override> tag.
/// \param s is the output stream
/// \param glb is the Architecture
void Override::saveXml(ostream &s,Architecture *glb) const

{
  if (forcegoto.empty() && deadcodedelay.empty() && indirectover.empty() && protoover.empty() &&
      multistagejump.empty() && flowoverride.empty())
    return;
  s << "<override>\n";

  map<Address,Address>::const_iterator iter;

  for(iter=forcegoto.begin();iter!=forcegoto.end();++iter) {
    s << "<forcegoto>";
    (*iter).first.saveXml(s);
    (*iter).second.saveXml(s);
    s << "</forcegoto>\n";
  }

  for(int4 i=0;i<deadcodedelay.size();++i) {
    if (deadcodedelay[i] < 0) continue;
    AddrSpace *spc = glb->getSpace(i);
    s << "<deadcodedelay";
    a_v(s,"space",spc->getName());
    a_v_i(s,"delay",deadcodedelay[i]);
    s << "/>\n";
  }

  for(iter=indirectover.begin();iter!=indirectover.end();++iter) {
    s << "<indirectoverride>";
    (*iter).first.saveXml(s);
    (*iter).second.saveXml(s);
    s << "</indirectoverride>\n";
  }

  map<Address,FuncProto *>::const_iterator fiter;

  for(fiter=protoover.begin();fiter!=protoover.end();++fiter) {
    s << "<protooverride>";
    (*fiter).first.saveXml(s);
    (*fiter).second->saveXml(s);
    s << "</protooverride>\n";
  }

  for(int4 i=0;i<multistagejump.size();++i) {
    s << "<multistagejump>";
    multistagejump[i].saveXml(s);
    s << "</multistagejump>";
  }

  map<Address,uint4>::const_iterator titer;
  for(titer=flowoverride.begin();titer!=flowoverride.end();++titer) {
    s << "<flow";
    a_v(s,"type",typeToString( (*titer).second ));
    s << ">";
    (*titer).first.saveXml(s);
    s << "</flow>\n";
  }

  s << "</override>\n";

}

/// \brief Read in override commands from XML
///
/// \param el is the root \<override> element
/// \param glb is the Architecture
void Override::restoreXml(const Element *el,Architecture *glb)

{
  const List &list(el->getChildren());
  List::const_iterator iter;

  for(iter=list.begin();iter!=list.end();++iter) {
    const Element *subel = *iter;

    if (subel->getName() == "indirectoverride") {
      const List &list2(subel->getChildren());
      List::const_iterator iter2 = list2.begin();
      Address callpoint = Address::restoreXml(*iter2,glb);
      ++iter2;
      Address directcall = Address::restoreXml(*iter2,glb);
      insertIndirectOverride(callpoint,directcall);
    }
    else if (subel->getName() == "protooverride") {
      const List &list2(subel->getChildren());
      List::const_iterator iter2 = list2.begin();
      Address callpoint = Address::restoreXml(*iter2,glb);
      ++iter2;
      FuncProto *fp = new FuncProto();
      fp->setInternal(glb->defaultfp,glb->types->getTypeVoid());
      fp->restoreXml(*iter2,glb);
      insertProtoOverride(callpoint,fp);
    }
    else if (subel->getName() == "forcegoto") {
      const List &list2(subel->getChildren());
      List::const_iterator iter2 = list2.begin();
      Address targetpc = Address::restoreXml(*iter2,glb);
      ++iter2;
      Address destpc = Address::restoreXml(*iter2,glb);
      insertForceGoto(targetpc,destpc);
    }
    else if (subel->getName() == "deadcodedelay") {
      int4 delay = -1;
      istringstream s(subel->getAttributeValue("delay"));
      s.unsetf(ios::dec | ios::hex | ios::oct);
      s >> delay;
      AddrSpace *spc = glb->getSpaceByName( subel->getAttributeValue("space"));
      if ((spc == (AddrSpace *)0)||(delay < 0))
	throw LowlevelError("Bad deadcodedelay tag");
      insertDeadcodeDelay(spc,delay);
    }
    else if (subel->getName() == "multistagejump") {
      const Element *tmpel = subel->getChildren().front();
      Address callpoint = Address::restoreXml(tmpel,glb);
      insertMultistageJump(callpoint);
    }
    else if (subel->getName() == "multistagejump") {
      const Element *tmpel = subel->getChildren().front();
      Address callpoint = Address::restoreXml(tmpel,glb);
      insertMultistageJump(callpoint);
    }
    else if (subel->getName() == "flow") {
      uint4 type = stringToType(subel->getAttributeValue("type"));
      const Element *tmpel = subel->getChildren().front();
      Address addr = Address::restoreXml(tmpel,glb);
      if ((type == Override::NONE)||(addr.isInvalid()))
	throw LowlevelError("Bad flowoverride tag");
      insertFlowOverride(addr,type);
    }
  }

}

/// \param tp is the override type
/// \return the corresponding name string
string Override::typeToString(uint4 tp)

{
  if (tp == Override::BRANCH)
    return "branch";
  if (tp == Override::CALL)
    return "call";
  if (tp == Override::CALL_RETURN)
    return "callreturn";
  if (tp == Override::RETURN)
    return "return";
  return "none";
}

/// \param nm is the override name
/// \return the override enumeration type
uint4 Override::stringToType(const string &nm)

{
  if (nm == "branch")
    return Override::BRANCH;
  else if (nm == "call")
    return Override::CALL;
  else if (nm == "callreturn")
    return Override::CALL_RETURN;
  else if (nm == "return")
    return Override::RETURN;
  return Override::NONE;
}
