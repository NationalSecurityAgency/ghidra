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
#include "dynamic.hh"
#include "funcdata.hh"
#include "crc32.hh"

// Table for how to hash opcodes, lumps certain operators (i.e. ADD SUB PTRADD PTRSUB) into one hash
// zero indicates the operator should be skipped
uint4 DynamicHash::transtable[] = {
  0,
  CPUI_COPY,  CPUI_LOAD,  CPUI_STORE,  CPUI_BRANCH,  CPUI_CBRANCH,  CPUI_BRANCHIND,

  CPUI_CALL,  CPUI_CALLIND,  CPUI_CALLOTHER,  CPUI_RETURN,

  CPUI_INT_EQUAL, CPUI_INT_EQUAL, // NOT_EQUAL hashes same as EQUAL
  CPUI_INT_SLESS, CPUI_INT_SLESS, // SLESSEQUAL hashes same as SLESS
  CPUI_INT_LESS, CPUI_INT_LESS,	// LESSEQUAL hashes same as LESS

  CPUI_INT_ZEXT,  CPUI_INT_SEXT,
  CPUI_INT_ADD,  CPUI_INT_ADD,	// SUB hases same as ADD
  CPUI_INT_CARRY,  CPUI_INT_SCARRY,  CPUI_INT_SBORROW,
  CPUI_INT_2COMP,  CPUI_INT_NEGATE,

  CPUI_INT_XOR,  CPUI_INT_AND,  CPUI_INT_OR,  CPUI_INT_MULT, // LEFT hases same as MULT
  CPUI_INT_RIGHT,  CPUI_INT_SRIGHT,
  CPUI_INT_MULT,  CPUI_INT_DIV,  CPUI_INT_SDIV,  CPUI_INT_REM,  CPUI_INT_SREM,

  CPUI_BOOL_NEGATE,  CPUI_BOOL_XOR,  CPUI_BOOL_AND,  CPUI_BOOL_OR,

  CPUI_FLOAT_EQUAL,  CPUI_FLOAT_EQUAL, // NOTEQUAL hases same as EQUAL
  CPUI_FLOAT_LESS,  CPUI_FLOAT_LESS, // LESSEQUAL hashes same as EQUAL
  0,				// Unused slot - skip
  CPUI_FLOAT_NAN,
 
  CPUI_FLOAT_ADD,  CPUI_FLOAT_DIV,  CPUI_FLOAT_MULT,  CPUI_FLOAT_ADD, // SUB hashes same as ADD
  CPUI_FLOAT_NEG,  CPUI_FLOAT_ABS, CPUI_FLOAT_SQRT,

  CPUI_FLOAT_INT2FLOAT,  CPUI_FLOAT_FLOAT2FLOAT,  CPUI_FLOAT_TRUNC,  CPUI_FLOAT_CEIL,  CPUI_FLOAT_FLOOR,
  CPUI_FLOAT_ROUND,

  CPUI_MULTIEQUAL,  CPUI_INDIRECT,  CPUI_PIECE,  CPUI_SUBPIECE,

  0,				// CAST is skipped
  CPUI_INT_ADD,  CPUI_INT_ADD, 	// PTRADD and PTRSUB hash same as INT_ADD
  CPUI_SEGMENTOP, CPUI_CPOOLREF, CPUI_NEW, CPUI_INSERT, CPUI_EXTRACT, CPUI_POPCOUNT
  
};

/// These edges are sorted to provide consistency to the hash
/// The sort is based on the PcodeOp sequence number first, then the Varnode slot
/// \param op2 is the edge to compare \b this to
/// \return \b true if \b this should be ordered before the other edge
bool ToOpEdge::operator<(const ToOpEdge &op2) const

{
  const Address &addr1( op->getSeqNum().getAddr() );
  const Address &addr2( op2.op->getSeqNum().getAddr() );
  if (addr1 != addr2)
    return (addr1 < addr2);
  uintm ord1 = op->getSeqNum().getOrder();
  uintm ord2 = op2.op->getSeqNum().getOrder();
  if (ord1 != ord2)
    return (ord1 < ord2);
  return (slot < op2.slot);
}

/// The hash accumulates:
///   - the Varnode slot
///   - the address of the PcodeOp
///   - the op-code of the PcodeOp
///
/// The op-codes are translated so that the hash is invariant under
/// common variants.
/// \param reg is the incoming hash accumulator value
/// \return the accumulator value with \b this edge folded in
uint4 ToOpEdge::hash(uint4 reg) const

{
  reg = crc_update(reg,(uint4)slot);
  reg = crc_update(reg,DynamicHash::transtable[op->code()]);
  uintb val = op->getSeqNum().getAddr().getOffset();
  int4 sz = op->getSeqNum().getAddr().getAddrSize();
  for(int4 i=0;i<sz;++i) {
    reg = crc_update(reg,(uint4)val); // Hash in the address
    val >>= 8;
  }
  return reg;
}

/// When building the edge, certain p-code ops (CAST) are effectively ignored so that
/// we get the same hash whether or not these ops are present.
/// \param vn is the given Varnode
void DynamicHash::buildVnUp(const Varnode *vn)
  
{
  const PcodeOp *op;
  for(;;) {
    if (!vn->isWritten()) return;
    op = vn->getDef();
    if (transtable[op->code()] != 0) break; // Do not ignore this operation
    vn = op->getIn(0);
  }
  opedge.push_back(ToOpEdge(op,-1));
}

/// When building edges, certain p-code ops (CAST) are effectively ignored so that
/// we get the same hash whether or not these ops are present.
/// \param vn is the given Varnode
void DynamicHash::buildVnDown(const Varnode *vn)
  
{
  list<PcodeOp *>::const_iterator iter;
  uint4 insize = opedge.size();
  
  for(iter=vn->beginDescend();iter!=vn->endDescend();++iter) {
    const PcodeOp *op = *iter;
    const Varnode *tmpvn = vn;
    while(transtable[op->code()]==0) {
      tmpvn = op->getOut();
      if (tmpvn == (const Varnode *)0) {
	op = (const PcodeOp *)0;
	break;
      }
      op = tmpvn->loneDescend();
      if (op == (const PcodeOp *)0) break;
    }
    if (op == (const PcodeOp *)0) continue;
    int4 slot = op->getSlot(tmpvn);
    opedge.push_back(ToOpEdge(op,slot));
  }
  if ((uint4)opedge.size()-insize > 1)
    sort(opedge.begin()+insize,opedge.end());
}

/// \param op is the given PcodeOp thats already in the sub-graph
void DynamicHash::buildOpUp(const PcodeOp *op)

{
  for(int4 i=0;i<op->numInput();++i) {
    const Varnode *vn = op->getIn(i);
    vnedge.push_back(vn);
  }
}

/// \param op is the given PcodeOp thats already in the sub-graph
void DynamicHash::buildOpDown(const PcodeOp *op)

{
  const Varnode *vn = op->getOut();
  if (vn == (const Varnode *)0) return;
  vnedge.push_back(vn);
}

void DynamicHash::gatherUnmarkedVn(void)

{
  for(int4 i=0;i<vnedge.size();++i) {
    const Varnode *vn = vnedge[i];
    if (vn->isMark()) continue;
    markvn.push_back(vn);
    vn->setMark();
  }
  vnedge.clear();
}

void DynamicHash::gatherUnmarkedOp(void)

{
  for(;opedgeproc<opedge.size();++opedgeproc) {
    const PcodeOp *op = opedge[opedgeproc].getOp();
    if (op->isMark()) continue;
    markop.push_back(op);
    op->setMark();
  }
}

void DynamicHash::clear(void)

{
  markop.clear();
  markvn.clear();
  vnedge.clear();
  opedge.clear();
}

/// A sub-graph is formed extending from the given Varnode as the root. The
/// method specifies how the sub-graph is extended. In particular:
///  - Method 0 is extends to just immediate p-code ops reading or writing root
///  - Method 1 extends to one more level of inputs from method 0.
///  - Method 2 extends to one more level of outputs from method 0.
///  - Method 3 extends to inputs and outputs
///
/// The resulting hash and address can be obtained after calling this method
/// through getHash() and getAddress().
/// \param root is the given root Varnode
/// \param method is the hashing method to use: 0, 1, 2, 3
void DynamicHash::calcHash(const Varnode *root,uint4 method)

{
  vnproc = 0;
  opproc = 0;
  opedgeproc = 0;

  vnedge.push_back(root);
  gatherUnmarkedVn();
  for(uint4 i=vnproc;i<markvn.size();++i)
    buildVnUp(markvn[i]);
  for(;vnproc<markvn.size();++vnproc)
    buildVnDown(markvn[vnproc]);

  switch(method) {
  case 0:
    break;
  case 1:
    gatherUnmarkedOp();
    for(;opproc<markop.size();++opproc)
      buildOpUp(markop[opproc]);
    
    gatherUnmarkedVn();
    for(;vnproc<markvn.size();++vnproc)
      buildVnUp(markvn[vnproc]);
    break;
  case 2:
    gatherUnmarkedOp();
    for(;opproc<markop.size();++opproc)
      buildOpDown(markop[opproc]);

    gatherUnmarkedVn();
    for(;vnproc<markvn.size();++vnproc)
      buildVnDown(markvn[vnproc]);
    break;
  case 3:
    gatherUnmarkedOp();
    for(;opproc<markop.size();++opproc)
      buildOpUp(markop[opproc]);

    gatherUnmarkedVn();
    for(;vnproc<markvn.size();++vnproc)
      buildVnDown(markvn[vnproc]);
    break;
  default:
    break;
  }
    
  for(uint4 i=0;i<markvn.size();++i) // Clear our marks
    markvn[i]->clearMark();
  for(uint4 i=0;i<markop.size();++i)
    markop[i]->clearMark();

  if (opedge.size() == 0) {
    hash = (uint8)0;
    addrresult = Address();
    return;
  }

  uint4 reg = 0x3ba0fe06;	// Calculate the 32-bit hash

  // Hash in information about the root
  reg = crc_update(reg,(uint4)root->getSize());
  if (root->isConstant()) {
    uintb val = root->getOffset();
    for(int4 i=0;i<root->getSize();++i) {
      reg = crc_update(reg,(uint4)val);
      val >>= 8;
    }
  }

  for(uint4 i=0;i<opedge.size();++i)
    reg = opedge[i].hash(reg);

  // Build the final 64-bit hash
  const PcodeOp *op = (const PcodeOp *)0;
  int4 slot = 0;
  uint4 ct;
  bool attachedop = true;
  for(ct=0;ct<opedge.size();++ct) { // Find op that is directly attached to -root- i.e. not a skip op
    op = opedge[ct].getOp();
    slot = opedge[ct].getSlot();
    if ((slot < 0) && (op->getOut() == root)) break;
    if ((slot >=0) && (op->getIn(slot)==root)) break;
  }
  if (ct == opedge.size()) {	// If everything attached to the root was a skip op
    op = opedge[0].getOp();	// Return op that is not attached directly
    slot = opedge[0].getSlot();
    attachedop = false;
  }

  // 15 bits unused
  hash = attachedop ? 0 : 1;
  hash <<= 4;
  hash |= method;		// 4-bits
  hash <<= 7;
  hash |= (uint8)op->code();	// 7-bits
  hash <<= 5;
  hash |= (uint8)(slot & 0x1f);	// 5-bits
  
  hash <<= 32;
  hash |= (uint8)reg;		// 32-bits for the neighborhood hash
  addrresult = op->getSeqNum().getAddr();
}

/// Collect the set of Varnodes at the same address as the given Varnode.
/// Starting with method 0, increment the method and calculate hashes
/// of the Varnodes until the given Varnode has a unique hash within the set.
/// The resulting hash and address can be obtained after calling this method
/// through getHash() and getAddress().
///
/// In the rare situation that the last method still does not yield a unique hash,
/// the hash encodes:
///   - the smallest number of hash collisions
///   - the method that produced the smallest number of hash collisions
///   - the position of the root within the collision list
///
/// For most cases, this will still uniquely identify the root Varnode.
/// \param root is the given root Varnode
/// \param fd is the function (holding the data-flow graph)
void DynamicHash::uniqueHash(const Varnode *root,Funcdata *fd)

{
  vector<Varnode *> vnlist;
  vector<Varnode *> vnlist2;
  vector<Varnode *> champion;
  uint4 method;
  uint8 tmphash;
  Address tmpaddr;
  uint4 maxduplicates = 8;

  for(method=0;method<4;++method) {
    clear();
    calcHash(root,method);
    if (hash == 0) return;	// Can't get a good hash
    tmphash = hash;
    tmpaddr = addrresult;
    vnlist.clear();
    vnlist2.clear();
    gatherFirstLevelVars(vnlist,fd,tmpaddr,tmphash);
    for(uint4 i=0;i<vnlist.size();++i) {
      Varnode *tmpvn = vnlist[i];
      clear();
      calcHash(tmpvn,method);
      if (hash == tmphash) {	// Hash collision
	vnlist2.push_back(tmpvn);
	if (vnlist2.size()>maxduplicates) break;
      }
    }
    if (vnlist2.size() <= maxduplicates) {
      if ((champion.size()==0)||(vnlist2.size() < champion.size())) {
	champion = vnlist2;
	if (champion.size()==1) break; // Current hash is unique
      }
    }
  }
  if (champion.empty()) {
    hash = (uint8)0;
    addrresult = Address();	// Couldn't find a unique hash
    return;
  }
  uint4 total = (uint4)champion.size() - 1; // total is in range [0,maxduplicates-1]
  uint4 pos;
  for(pos=0;pos<=total;++pos)
    if (champion[pos] == root) break;
  if (pos > total) {
    hash = (uint8)0;
    addrresult = Address();
    return;
  }
  hash = tmphash | ((uint8)pos << 49); // Store three bits for position with list of duplicate hashes
  hash |= ((uint8)total << 52);	// Store three bits for total number of duplicate hashes
  addrresult = tmpaddr;
}

/// \brief Given an address and hash, find the unique matching Varnode
///
/// The method, number of collisions, and position are pulled out of the hash.
/// Hashes for the method are performed at Varnodes linked to the given address,
/// and the Varnode which matches the hash (and the position) is returned.
/// If the number of collisions for the hash does not match, this method
/// will not return a Varnode, even if the position looks valid.
/// \param fd is the function containing the data-flow
/// \param addr is the given address
/// \param h is the hash
/// \return the matching Varnode or NULL
Varnode *DynamicHash::findVarnode(const Funcdata *fd,const Address &addr,uint8 h)

{
  uint4 method = getMethodFromHash(h);
  uint4 total = getTotalFromHash(h);
  uint4 pos = getPositionFromHash(h);
  clearTotalPosition(h);
  vector<Varnode *> vnlist;
  vector<Varnode *> vnlist2;
  gatherFirstLevelVars(vnlist,fd,addr,h);
  for(uint4 i=0;i<vnlist.size();++i) {
    Varnode *tmpvn = vnlist[i];
    clear();
    calcHash(tmpvn,method);
    if (hash == h)
      vnlist2.push_back(tmpvn);
  }
  if (total != vnlist2.size()) return (Varnode *)0;
  return vnlist2[pos];
}

/// \brief Get the Varnodes immediately attached to PcodeOps at the given address
///
/// Varnodes can be either inputs or outputs to the PcodeOps. The op-code, slot, and
/// attachment boolean encoded in the hash are used to further filter the
/// PcodeOp and Varnode objects. Varnodes are passed back in sequence with a list container.
/// \param varlist is the container that will hold the matching Varnodes
/// \param fd is the function holding the data-flow
/// \param addr is the given address
/// \param h is the given hash
void DynamicHash::gatherFirstLevelVars(vector<Varnode *> &varlist,const Funcdata *fd,const Address &addr,uint8 h)

{
  OpCode opc = getOpCodeFromHash(h);
  int4 slot = getSlotFromHash(h);
  bool isnotattached = getIsNotAttached(h);
  PcodeOpTree::const_iterator iter = fd->beginOp(addr);
  PcodeOpTree::const_iterator enditer = fd->endOp(addr);

  while(iter!=enditer) {
    PcodeOp *op = (*iter).second;
    ++iter;
    if (op->code() != opc) continue;
    if (slot <0) {
      Varnode *vn = op->getOut();
      if (vn != (Varnode *)0) {
	if (isnotattached) {	// If original varnode was not attached to (this) op
	  op = vn->loneDescend();
	  if (op != (PcodeOp *)0) {
	    if (transtable[op->code()] == 0) { // Check for skipped op
	      vn = op->getOut();
	      if (vn == (Varnode *)0) continue;
	    }
	  }
	}
	varlist.push_back(vn);
      }
    }
    else if (slot < op->numInput()) {
      Varnode *vn = op->getIn(slot);
      if (isnotattached) {
	op = vn->getDef();
	if ((op != (PcodeOp *)0)&&(transtable[op->code()]==0))
	  vn = op->getIn(0);
      }
      varlist.push_back(vn);
    }
  }
}

/// The hash encodes the input \e slot the root Varnode was attached to in its PcodeOp.
/// \param h is the hash value
/// \return the slot index or -1 if the Varnode was attached as output
int4 DynamicHash::getSlotFromHash(uint8 h)

{
  int4 res = (int4)((h>>32)&0x1f);
  if (res == 31)
    res = -1;
  return res;
}

/// The hash encodes the \e method used to produce it.
/// \param h is the hash value
/// \return the method: 0, 1, 2, 3
uint4 DynamicHash::getMethodFromHash(uint8 h)

{
  return (uint4)((h>>44)&0xf);
}

/// The hash encodes the op-code of the p-code op attached to the root Varnode
/// \param h is the hash value
/// \return the op-code
OpCode DynamicHash::getOpCodeFromHash(uint8 h)

{
  return (OpCode)((h>>37)&0x7f);
}

/// The hash encodes the position of the root Varnode within the list of hash collisions
/// \param h is the hash value
/// \return the position of the root
uint4 DynamicHash::getPositionFromHash(uint8 h)

{
  return (uint4)((h>>49)&7);
}

/// The hash encodes the total number of collisions for that hash
/// \param h is the hash value
/// \return the total number of collisions
uint4 DynamicHash::getTotalFromHash(uint8 h)

{
  return ((uint4)((h>>52)&7)+1);
}

/// The hash encodes whether or not the root was directly attached to its PcodeOp
/// \param h is the hash value
/// \return \b true if the root was not attached
bool DynamicHash::getIsNotAttached(uint8 h)

{
  return (((h>>48)&1)!=0);
}

/// The position and total collisions fields are set by the uniqueness and
/// need to be cleared when comparing raw hashes.
/// \param h is a reference to the hash to modify
void DynamicHash::clearTotalPosition(uint8 &h)

{
  uint8 val = 0x3f;
  val <<= 49;
  val = ~val;
  h &= val;
}
