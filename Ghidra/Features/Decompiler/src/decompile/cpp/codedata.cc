/* ###
 * IP: GHIDRA
 * NOTE: Target command uses BFD stuff which is GPL 3
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
#include "codedata.hh"
#include "loadimage_bfd.hh"

// Constructing this registers the capability
IfaceCodeDataCapability IfaceCodeDataCapability::ifaceCodeDataCapability;

IfaceCodeDataCapability::IfaceCodeDataCapability(void)

{
  name = "codedata";
}

void IfaceCodeDataCapability::registerCommands(IfaceStatus *status)

{
  status->registerCom(new IfcCodeDataInit(),"codedata","init");
  status->registerCom(new IfcCodeDataTarget(),"codedata","target");
  status->registerCom(new IfcCodeDataRun(),"codedata","run");
  status->registerCom(new IfcCodeDataDumpModelHits(),"codedata","dump","hits");
  status->registerCom(new IfcCodeDataDumpCrossRefs(),"codedata","dump","crossrefs");
  status->registerCom(new IfcCodeDataDumpStarts(),"codedata","dump","starts");
  status->registerCom(new IfcCodeDataDumpUnlinked(),"codedata","dump","unlinked");
  status->registerCom(new IfcCodeDataDumpTargetHits(),"codedata","dump","targethits");
}

void DisassemblyEngine::init(const Translate *t)

{
  trans = t;
  jumpaddr.clear();
  targetoffsets.clear();
}

void DisassemblyEngine::dump(const Address &addr,OpCode opc,VarnodeData *outvar,VarnodeData *vars,int4 isize)

{
  lastop = opc;
  switch(opc) {
  case CPUI_CALL:
    hascall = true;
    // fallthru
  case CPUI_BRANCH:
  case CPUI_CBRANCH:
    jumpaddr.push_back(Address(vars[0].space,vars[0].offset));
    break;
  case CPUI_COPY:
  case CPUI_BRANCHIND:
  case CPUI_CALLIND:
    if (targetoffsets.end() != targetoffsets.find( vars[0].offset )) {
      hitsaddress = true;
      targethit = vars[0].offset;
    }
    break;
  case CPUI_LOAD:
    if (targetoffsets.end() != targetoffsets.find( vars[1].offset )) {
      hitsaddress = true;
      targethit = vars[1].offset;
    }
    break;
  default:
    break;
  }
}

void DisassemblyEngine::disassemble(const Address &addr,DisassemblyResult &res)

{
  jumpaddr.clear();
  lastop = CPUI_COPY;
  hascall = false;
  hitsaddress = false;
  res.flags = 0;
  try {
    res.length = trans->oneInstruction(*this,addr);
  } catch(BadDataError &err) {
    res.success = false;
    return;
  } catch(DataUnavailError &err) {
    res.success = false;
    return;
  } catch(UnimplError &err) {
    res.length = err.instruction_length;
  }
  res.success = true;
  if (hascall)
    res.flags |= CodeUnit::call;
  if (hitsaddress) {
    res.flags |= CodeUnit::targethit;
    res.targethit = targethit;
  }
  Address lastaddr = addr + res.length;
  switch(lastop) {
  case CPUI_BRANCH:
  case CPUI_BRANCHIND:
    if (hitsaddress)
      res.flags |= CodeUnit::thunkhit; // Hits target via indirect jump
    break;
  case CPUI_RETURN:
    break;
  default:
    res.flags |= CodeUnit::fallthru;
    break;
  }
  for(int4 i=0;i<jumpaddr.size();++i) {
    if (jumpaddr[i] == lastaddr)
      res.flags |= CodeUnit::fallthru;
    else if (jumpaddr[i] != addr) {
      res.flags |= CodeUnit::jump;
      res.jumpaddress = jumpaddr[i];
    }
  }
}

void CodeDataAnalysis::init(Architecture *g)

{
  glb = g;
  disengine.init(glb->translate);
  alignment = glb->translate->getAlignment();
  modelhits.clear();
  codeunit.clear();
  fromto_crossref.clear();
  tofrom_crossref.clear();
  taintlist.clear();
  unlinkedstarts.clear();
  targethits.clear();
  targets.clear();
}

void CodeDataAnalysis::pushTaintAddress(const Address &addr)

{
  map<Address,CodeUnit>::iterator iter;

  iter = codeunit.upper_bound(addr); // First after
  if (iter == codeunit.begin()) return;
  --iter;			// Last before or equal
  CodeUnit &cu((*iter).second);
  if ((*iter).first.getOffset() + cu.size-1 <addr.getOffset()) return;
  if ((cu.flags & CodeUnit::notcode)!= 0) return; // Already visited
  taintlist.push_back(iter);
}

void CodeDataAnalysis::processTaint(void)

{
  map<Address,CodeUnit>::iterator iter = taintlist.back();
  taintlist.pop_back();

  CodeUnit &cu((*iter).second);
  cu.flags |= CodeUnit::notcode;
  Address startaddr = (*iter).first;
  Address endaddr = startaddr + cu.size;
  if (iter != codeunit.begin()) {
    --iter;
    CodeUnit &cu2( (*iter).second);
    if ((cu2.flags & (CodeUnit::fallthru&CodeUnit::notcode))==CodeUnit::fallthru) { // not "notcode" and fallthru
      Address addr2 = (*iter).first + cu.size;
      if (addr2 == startaddr)
	taintlist.push_back(iter);
    }
  }
  map<AddrLink,uint4>::iterator ftiter,diter,enditer;
  ftiter = fromto_crossref.lower_bound(AddrLink(startaddr));
  enditer = fromto_crossref.lower_bound(AddrLink(endaddr));
  fromto_crossref.erase(ftiter,enditer); // Erase all cross-references coming out of this block
  
  ftiter = tofrom_crossref.lower_bound(AddrLink(startaddr));
  enditer = tofrom_crossref.lower_bound(AddrLink(endaddr));
  while(ftiter != enditer) {
    pushTaintAddress((*ftiter).first.b);
    diter = ftiter;
    ++ftiter;
    tofrom_crossref.erase(diter);
  }
}

Address CodeDataAnalysis::commitCodeVec(const Address &addr,vector<CodeUnit> &codevec,map<AddrLink,uint4> &fromto_vec)

{ // Commit all the code units in the vector, build all the crossrefs
  Address curaddr = addr;
  for(int4 i=0;i<codevec.size();++i) {
    codeunit[curaddr] = codevec[i];
    curaddr = curaddr + codevec[i].size;
  }
  map<AddrLink,uint4>::iterator citer;
  for(citer=fromto_vec.begin();citer!=fromto_vec.end();++citer) {
    const AddrLink &fromto( (*citer).first );
    fromto_crossref[ fromto ] = (*citer).second;
    AddrLink tofrom( fromto.b, fromto.a );
    tofrom_crossref[ tofrom ] = (*citer).second;
  }
  return curaddr;
}

void CodeDataAnalysis::clearHitBy(void)

{ // Clear all the "hit_by" flags from all code units
  map<Address,CodeUnit>::iterator iter;

  for(iter=codeunit.begin();iter!=codeunit.end();++iter) {
    CodeUnit &cu( (*iter).second );
    cu.flags &= ~ (CodeUnit::hit_by_fallthru|CodeUnit::hit_by_jump|CodeUnit::hit_by_call);
  }
}

void CodeDataAnalysis::clearCrossRefs(const Address &addr,const Address &endaddr)

{ // Clear all crossrefs originating from [addr,endaddr)
  map<AddrLink,uint4>::iterator startiter,iter,enditer,tfiter;

  startiter = fromto_crossref.lower_bound(AddrLink(addr));
  enditer = fromto_crossref.lower_bound(AddrLink(endaddr));
  for(iter=startiter;iter!=enditer;++iter) {
    const AddrLink &fromto( (*iter).first );
    tfiter = tofrom_crossref.find( AddrLink(fromto.b,fromto.a) );
    if (tfiter != tofrom_crossref.end())
      tofrom_crossref.erase(tfiter);
  }
  fromto_crossref.erase(startiter,enditer);
}

void CodeDataAnalysis::addTarget(const string &nm,const Address &addr,uint4 mask)

{ // Add a target thunk to be searched for
  TargetFeature &targfeat(targets[addr]);
  targfeat.name = nm;
  targfeat.featuremask = mask;
  disengine.addTarget(addr);	// Tell the disassembler to search for address
}

void CodeDataAnalysis::clearCodeUnits(const Address &addr,const Address &endaddr)

{ // Clear all the code units in [addr,endaddr)
  map<Address,CodeUnit>::iterator iter,enditer;

  iter = codeunit.lower_bound(addr);
  enditer = codeunit.lower_bound(endaddr);
  codeunit.erase(iter,enditer);
  clearCrossRefs(addr,endaddr);
}

Address CodeDataAnalysis::disassembleBlock(const Address &addr,const Address &endaddr)

{
  DisassemblyResult disresult;
  vector<CodeUnit> codevec;
  map<AddrLink,uint4> fromto_vec;
  bool flowin = false;
  bool hardend = false;

  Address curaddr = addr;
  map<Address,CodeUnit>::iterator iter;
  iter = codeunit.lower_bound(addr);
  Address lastaddr;
  if (iter != codeunit.end()) {
    lastaddr = (*iter).first;
    if (endaddr < lastaddr) {
      lastaddr = endaddr;
      hardend = true;
    }
  }
  else {
    lastaddr = endaddr;
    hardend = true;
  }
  for(;;) {
    disengine.disassemble(curaddr,disresult);
    codevec.emplace_back();
    if (!disresult.success) {
      codevec.back().flags = CodeUnit::notcode;
      codevec.back().size = 1;
      curaddr = curaddr + 1;
      break;
    }
    if ((disresult.flags & CodeUnit::jump)!=0) {
      fromto_vec[ AddrLink(curaddr,disresult.jumpaddress)] = disresult.flags;
    }
    codevec.back().flags = disresult.flags;
    codevec.back().size = disresult.length;
    curaddr = curaddr + disresult.length;
    while(lastaddr < curaddr) {
      if ((!hardend)&&((*iter).second.flags & CodeUnit::notcode)!=0) {
	if ((*iter).second.size == 1) {
	  map<Address,CodeUnit>::iterator iter2 = iter;
	  ++iter;		// We delete the bad disassembly, as it looks like it is unaligned
	  codeunit.erase(iter2);
	  if (iter != codeunit.end()) {
	    lastaddr = (*iter).first;
	    if (endaddr < lastaddr) {
	      lastaddr = endaddr;
	      hardend = true;
	    }
	  }
	  else {
	    lastaddr = endaddr;
	    hardend = true;
	  }
	}
	else {
	  disresult.success = false;
	  flowin = true;
	  break;
	}
      }
      else {
	disresult.success = false;
	break;
      }
    }
    if (!disresult.success)
      break;
    if (curaddr == lastaddr) {
      if (((*iter).second.flags & CodeUnit::notcode)!=0) {
	flowin = true;
	break;
      }
    }
    if (((disresult.flags & CodeUnit::fallthru)==0)||(curaddr==lastaddr)) {  // found the end of a block
      return commitCodeVec(addr,codevec,fromto_vec);
    }
  }
  // If we reach here, we have bad disassembly of some sort
  CodeUnit &cu( codeunit[ addr ] );
  cu.flags = CodeUnit::notcode;
  if (hardend && (lastaddr < curaddr))
    curaddr = lastaddr;
  int4 wholesize = curaddr.getOffset() - addr.getOffset();
  if ((!flowin) && (wholesize < 10)) {
    wholesize = 1;
  }
  cu.size = wholesize;
  curaddr = addr + cu.size;
  return curaddr;
}

void CodeDataAnalysis::disassembleRange(const Range &range)

{
  Address addr = range.getFirstAddr();
  Address lastaddr = range.getLastAddr();
  while(addr <= lastaddr) {
    addr = disassembleBlock(addr,lastaddr);
  }
}

void CodeDataAnalysis::disassembleRangeList(const RangeList &rangelist)

{
  set<Range>::const_iterator iter,enditer;
  iter = rangelist.begin();
  enditer = rangelist.end();

  while(iter != enditer) {
    disassembleRange(*iter);
    ++iter;
  }
}

void CodeDataAnalysis::findNotCodeUnits(void)

{ // Mark any code units that have flow into "notcode" units as "notcode"
  // Remove any references to or from these units
  map<Address,CodeUnit>::iterator iter;

  // We spread the "notcode" attribute as a taint
  // We build the initial work list with known "notcode"
  for(iter=codeunit.begin();iter!=codeunit.end();++iter) {
    if (((*iter).second.flags & CodeUnit::notcode)!=0)
      taintlist.push_back(iter);
  }

  while(!taintlist.empty())	// Propagate taint along fallthru and crossref edges
    processTaint();
}

void CodeDataAnalysis::markFallthruHits(void)

{ // Mark every code unit that has another code unit fall into it
  map<Address,CodeUnit>::iterator iter;

  Address fallthruaddr((AddrSpace *)0,0);
  iter = codeunit.begin();
  for(iter=codeunit.begin();iter != codeunit.end();++iter) {
    CodeUnit &cu((*iter).second);
    if ((cu.flags & CodeUnit::notcode)!=0) continue;
    if (fallthruaddr == (*iter).first)
      cu.flags |= CodeUnit::hit_by_fallthru;
    if ((cu.flags & CodeUnit::fallthru)!=0)
      fallthruaddr = (*iter).first + cu.size;
  }
}

void CodeDataAnalysis::markCrossHits(void)

{ // Mark every codeunit hit by a call or jump
  map<AddrLink,uint4>::iterator iter;
  map<Address,CodeUnit>::iterator fiter;

  for(iter=tofrom_crossref.begin();iter!=tofrom_crossref.end();++iter) {
    fiter = codeunit.find((*iter).first.a);
    if (fiter == codeunit.end()) continue;
    uint4 fromflags = (*iter).second;
    CodeUnit &to( (*fiter).second );
    if ((fromflags & CodeUnit::call)!=0)
      to.flags |= CodeUnit::hit_by_call;
    else if ((fromflags & CodeUnit::jump)!=0)
      to.flags |= CodeUnit::hit_by_jump;
  }
}

void CodeDataAnalysis::addTargetHit(const Address &codeaddr,uintb targethit)

{
  Address funcstart = findFunctionStart( codeaddr );
  Address thunkaddr = Address(glb->translate->getDefaultCodeSpace(),targethit);
  uint4 mask;
  map<Address,TargetFeature>::const_iterator titer;
  titer = targets.find( thunkaddr );
  if (titer != targets.end())
    mask = (*titer).second.featuremask;
  else
    throw LowlevelError("Found thunk without a feature mask");
  targethits.emplace_back(funcstart,codeaddr,thunkaddr,mask);
}

void CodeDataAnalysis::resolveThunkHit(const Address &codeaddr,uintb targethit)

{ // Code unit make indirect jump to target
  // Assume the address of the jump is another level of thunk
  // Look for direct calls to it and include those as TargetHits
  map<AddrLink,uint4>::iterator iter,enditer;
  iter = tofrom_crossref.lower_bound(AddrLink(codeaddr));
  Address endaddr = codeaddr + 1;
  enditer = tofrom_crossref.lower_bound(AddrLink(endaddr));
  while(iter != enditer) {
    uint4 flags = (*iter).second;
    if ((flags & CodeUnit::call)!=0)
      addTargetHit( (*iter).first.b, targethit );
    ++iter;
  }
}

void CodeDataAnalysis::findUnlinked(void)

{ // Find all code units that have no jump/call/fallthru to them
  map<Address,CodeUnit>::iterator iter;

  for(iter=codeunit.begin();iter!=codeunit.end();++iter) {
    CodeUnit &cu( (*iter).second);
    if ((cu.flags & (CodeUnit::hit_by_fallthru|CodeUnit::hit_by_jump|
		     CodeUnit::hit_by_call|CodeUnit::notcode|
		     CodeUnit::errantstart))==0)
      unlinkedstarts.push_back((*iter).first);
    if ((cu.flags & (CodeUnit::targethit|CodeUnit::notcode))==CodeUnit::targethit) {
      Address codeaddr = (*iter).first;
      DisassemblyResult res;
      disengine.disassemble(codeaddr,res);
      if ((cu.flags & CodeUnit::thunkhit)!=0)
	resolveThunkHit(codeaddr,res.targethit);
      else
	addTargetHit( codeaddr, res.targethit );
    }
  }
}

bool CodeDataAnalysis::checkErrantStart(map<Address,CodeUnit>::iterator iter)

{
  int4 count=0;

  while(count < 1000) {
    CodeUnit &cu( (*iter).second);
    if ((cu.flags & (CodeUnit::hit_by_jump|CodeUnit::hit_by_call))!=0)
      return false;		// Something else jumped in
    if ((cu.flags & CodeUnit::hit_by_fallthru)==0) {
      cu.flags |= CodeUnit::errantstart;
      return true;
    }
    if (iter == codeunit.begin()) return false;
    --iter;
    count += 1;
  }
  return false;
}

bool CodeDataAnalysis::repairJump(const Address &addr,int4 max)

{ // Assume -addr- is a correct instruction start. Try to repair
  // disassembly for up to -max- instructions following it,
  // trying to get back on cut
  DisassemblyResult disresult;
  vector<CodeUnit> codevec;
  map<AddrLink,uint4> fromto_vec;
  Address curaddr = addr;
  map<Address,CodeUnit>::iterator iter;
  int4 count = 0;

  iter = codeunit.lower_bound(addr);
  if (iter == codeunit.end()) return false;
  for(;;) {
    count += 1;
    if (count >=max) return false;
    while ((*iter).first < curaddr) {
      ++iter;
      if (iter == codeunit.end()) return false;
    }
    if (curaddr == (*iter).first) break; // Back on cut
    disengine.disassemble(curaddr,disresult);
    if (!disresult.success) return false;
    codevec.emplace_back();
    if ((disresult.flags & CodeUnit::jump)!=0) {
      fromto_vec[ AddrLink(curaddr,disresult.jumpaddress) ] = disresult.flags;
    }
    codevec.back().flags = disresult.flags;
    codevec.back().size = disresult.length;
    curaddr = curaddr + disresult.length;
  }
  clearCodeUnits(addr,curaddr);
  commitCodeVec(addr,codevec,fromto_vec);
  return true;
}

void CodeDataAnalysis::findOffCut(void)

{
  map<AddrLink,uint4>::iterator iter;
  map<Address,CodeUnit>::iterator citer;

  iter = tofrom_crossref.begin();
  while(iter!=tofrom_crossref.end()) {
    Address addr = (*iter).first.a; // Destination of a jump
    citer = codeunit.lower_bound(addr);
    if (citer != codeunit.end()) {
      if ((*citer).first == addr) { // Not off cut
	CodeUnit &cu( (*citer).second );
	if ((cu.flags & (CodeUnit::hit_by_fallthru|CodeUnit::hit_by_call))==
	    (CodeUnit::hit_by_fallthru|CodeUnit::hit_by_call)) {
	  // Somebody falls through into the call
	  --citer;
	  checkErrantStart(citer);
	}
	++iter;
	continue;
      }
    }
    if (citer == codeunit.begin()) {
      ++iter;
      continue;
    }
    --citer;			// Last lessthan or equal
    if ((*citer).first == addr) {
      ++iter;
      continue; // on cut
    }
    Address endaddr = (*citer).first + (*citer).second.size;
    if (endaddr <= addr) {
      ++iter;
      continue;
    }
    if (!checkErrantStart(citer)) {
      ++iter;
      continue;
    }
    AddrLink addrlink = (*iter).first;
    repairJump(addr,10);	// This may delete tofrom_crossref nodes
    iter = tofrom_crossref.upper_bound(addrlink);
  }
}

Address CodeDataAnalysis::findFunctionStart(const Address &addr) const

{ // Find the starting address of a function containing the address addr
  map<AddrLink,uint4>::const_iterator iter;

  iter = tofrom_crossref.lower_bound( AddrLink(addr ) );
  while(iter != tofrom_crossref.begin()) {
    --iter;
    if (((*iter).second & CodeUnit::call)!=0)
      return (*iter).first.a;
  }
  return Address();		// Return invalid address
}

void CodeDataAnalysis::dumpModelHits(ostream &s) const

{
  set<Range>::const_iterator iter,enditer;
  iter = modelhits.begin();
  enditer = modelhits.end();
  while(iter != enditer) {
    uintb off = (*iter).getFirst();
    s << hex << "0x" << off << ' ';
    uintb endoff = (*iter).getLast();
    s << hex << "0x" << endoff;
    ++iter;
    if (iter != enditer) {
      off = (*iter).getFirst();
      s << ' ' << dec << (int4)(off-endoff);
    }
    s << endl;
  }
}

void CodeDataAnalysis::dumpCrossRefs(ostream &s) const

{
  map<AddrLink,uint4>::const_iterator iter;

  for(iter=fromto_crossref.begin();iter!=fromto_crossref.end();++iter) {
    AddrLink addrlink = (*iter).first;
    uint4 flags = (*iter).second;
    
    s << hex << "0x" << addrlink.a.getOffset() << " -> 0x" << addrlink.b.getOffset();
    if ((flags & CodeUnit::call)!=0)
      s << " call";
    s << endl;
  }
}

void CodeDataAnalysis::dumpFunctionStarts(ostream &s) const

{
  map<AddrLink,uint4>::const_iterator iter;

  for(iter=tofrom_crossref.begin();iter!=tofrom_crossref.end();++iter) {
    AddrLink addrlink = (*iter).first;
    uint4 flags = (*iter).second;
    
    if ((flags & CodeUnit::call)!=0)
      s << hex << "0x" << addrlink.a.getOffset() << endl;
  }
}

void CodeDataAnalysis::dumpUnlinked(ostream &s) const

{
  list<Address>::const_iterator iter;

  for(iter=unlinkedstarts.begin();iter!=unlinkedstarts.end();++iter) {
    s << hex << "0x" << (*iter).getOffset() << endl;
  }
}

void CodeDataAnalysis::dumpTargetHits(ostream &s) const

{ // Dump every code unit that refers to a target
  list<TargetHit>::const_iterator iter;

  for(iter=targethits.begin();iter!=targethits.end();++iter) {
    Address funcaddr = (*iter).funcstart;
    Address addr = (*iter).codeaddr;
    string nm = (*targets.find((*iter).thunkaddr)).second.name;
    if (!funcaddr.isInvalid())
      s << hex << funcaddr.getOffset() << ' ';
    else
      s << "nostart ";
    s << hex << addr.getOffset() << ' ' << nm << endl;
  }
}

void CodeDataAnalysis::runModel(void)

{
  LoadImage *loadimage = glb->loader;
  LoadImageSection secinfo;
  bool moresections;
  loadimage->openSectionInfo();
  Address lastaddr;
  do {
    moresections = loadimage->getNextSection(secinfo);
    Address endaddr = secinfo.address + secinfo.size;
    if (secinfo.size == 0) continue;
    if (lastaddr.isInvalid())
      lastaddr = endaddr;
    else if (lastaddr < endaddr)
      lastaddr = endaddr;

    if ((secinfo.flags & (LoadImageSection::unalloc|LoadImageSection::noload))==0) {
      modelhits.insertRange(secinfo.address.getSpace(),
			    secinfo.address.getOffset(),endaddr.getOffset());
    }
  } while(moresections);
  loadimage->closeSectionInfo();
  CodeUnit &cu( codeunit[lastaddr] );
  cu.size = 100;
  cu.flags = CodeUnit::notcode;
  disassembleRangeList(modelhits);
  findNotCodeUnits();
  markFallthruHits();
  markCrossHits();
  findOffCut();
  clearHitBy();
  markFallthruHits();
  markCrossHits();
  findUnlinked();
  targethits.sort();		// Sort the list of hits by function containing hit
}

void IfaceCodeDataCommand::setData(IfaceStatus *root,IfaceData *data)

{
  status = root;
  codedata = (CodeDataAnalysis *)data;
  dcp = (IfaceDecompData *)status->getData("decompile");
}

void IfcCodeDataInit::execute(istream &s)

{
  codedata->init(dcp->conf);
}

void IfcCodeDataTarget::execute(istream &s)

{
  string token;

  s >> ws;
  if (s.eof())
    throw IfaceParseError("Missing system call name");

  s >> token;
  vector<ImportRecord> irec;
  LoadImageBfd *loadbfd = (LoadImageBfd *) dcp->conf->loader;
  loadbfd->getImportTable(irec);
  int4 i;
  for(i=0;i<irec.size();++i) {
    if (irec[i].funcname == token) break;
  }
  if (i==irec.size())
    *status->fileoptr << "Unable to find reference to call " << token << endl;
  else {
    codedata->addTarget(irec[i].funcname,irec[i].thunkaddress,(uint4)1);
  }
}

void IfcCodeDataRun::execute(istream &s)

{
  codedata->runModel();
}

void IfcCodeDataDumpModelHits::execute(istream &s)

{
  codedata->dumpModelHits(*status->fileoptr);
}

void IfcCodeDataDumpCrossRefs::execute(istream &s)

{
  codedata->dumpCrossRefs(*status->fileoptr);
}

void IfcCodeDataDumpStarts::execute(istream &s)

{
  codedata->dumpFunctionStarts(*status->fileoptr);
}

void IfcCodeDataDumpUnlinked::execute(istream &s)

{
  codedata->dumpUnlinked(*status->fileoptr);
}

void IfcCodeDataDumpTargetHits::execute(istream &s)

{
  codedata->dumpTargetHits(*status->fileoptr);
}
