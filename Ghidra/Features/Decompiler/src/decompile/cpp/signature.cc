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
#include "signature.hh"
#include "crc32.hh"

namespace ghidra {

uint4 SigManager::settings = 0;		// User MUST set a valid settings
// The current suggested defaults
//    ((GraphSigManager::SIG_DONOTUSE_CONST |
//      GraphSigManager::SIG_COLLAPSE_INDNOISE)<<2)|1

AttributeId ATTRIB_BADDATA = AttributeId("baddata",145);
AttributeId ATTRIB_HASH = AttributeId("hash",146);
AttributeId ATTRIB_UNIMPL = AttributeId("unimpl",147);

ElementId ELEM_BLOCKSIG = ElementId("blocksig",258);
ElementId ELEM_CALL = ElementId("call",259);
ElementId ELEM_GENSIG = ElementId("gensig",260);
ElementId ELEM_MAJOR = ElementId("major",261);
ElementId ELEM_MINOR = ElementId("minor",262);
ElementId ELEM_COPYSIG = ElementId("copysig",263);
ElementId ELEM_SETTINGS = ElementId("settings",264);
ElementId ELEM_SIG = ElementId("sig",265);
ElementId ELEM_SIGNATUREDESC = ElementId("signaturedesc",266);
ElementId ELEM_SIGNATURES = ElementId("signatures",267);
ElementId ELEM_SIGSETTINGS = ElementId("sigsettings",268);
ElementId ELEM_VARSIG = ElementId("varsig",269);

static hashword hash_mixin(hashword val1,hashword val2)

{
  uint4 hashhi = (uint4)(val1>>32);
  uint4 hashlo = (uint4)val1;
  for(int4 i=0;i<8;++i) {
    uint4 tmphi = hashhi;
    uint4 tmplo = (uint4)val2;
    val2 >>= 8;
    hashhi = crc_update(hashhi,tmplo);
    hashlo = crc_update(hashlo,tmphi);
  }
  uint8 res = hashhi;
  res <<= 32;
  res |= hashlo;
  return res;
}

/// \param s is the given stream to write to
void Signature::print(ostream &s) const

{
  s << '*';
  printOrigin(s);
  s << " = 0x" << hex << setw(8) << setfill('0') << sig << endl;
}

/// The underlying hashes of the two features are compared as unsigned values.
/// \param op2 is the other feature to compare with \b this
/// \return -1, 0, or 1 if \b this is ordered before, equal to, or after the other feature
int4 Signature::compare(const Signature *op2) const

{
  if (sig != op2->sig)
    return (sig < op2->sig) ? -1 : 1;
  return 0;
}

/// A Varnode shadows another if it is defined by a COPY or INDIRECT op.  In this case, the
/// \b shadow field is filled in by following any chain of COPY and INDIRECT ops back to their input Varnode.
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::calculateShadow(const map<int4,SignatureEntry *> &sigMap)

{
  const Varnode *shadowVn = vn;
  for(;;) {
    op = shadowVn->getDef();
    if (op == (const PcodeOp *)0)
      break;
    OpCode opc = op->code();
    if (opc != CPUI_COPY && opc != CPUI_INDIRECT && opc != CPUI_CAST)
      break;
    shadowVn = op->getIn(0);
  }
  if (shadowVn != vn)
    shadow = mapToEntry(shadowVn,sigMap);
}

/// In most cases, the hash value is just the OpCode of the PcodeOp itself.
/// CPOOLREF ops are distinguished by hashing in the CPoolRecord tag type.
/// \param modifiers are the specific settings being used for signature generation
/// \return the PcodeOp hash value or 0 if there is no effective PcodeOp
hashword SignatureEntry::getOpHash(uint4 modifiers)

{
  if (op == (const PcodeOp *)0)
    return 0;
  OpCode opc = op->code();
  hashword ophash = (hashword)opc;
  // For constant pool operations, hash in the resolved tag type constant, which is the last input
  if (opc == CPUI_CPOOLREF)
    ophash = (ophash + 0xfeedface) ^ op->getIn(op->numInput()-1)->getOffset();
  return ophash;
}

/// A stand-alone COPY is incorporated as a feature differently from other Varnodes.
/// This method computes its hash once up front, and it is not updated iteratively as
/// with other SignatureEntry nodes.
/// \param modifiers are the specific settings being used for signature generation
void SignatureEntry::standaloneCopyHash(uint4 modifiers)

{
  hashword val = hashSize(vn,modifiers);
  val ^= 0xaf29e23b;
  if (vn->isPersist())
    val ^= (hashword) 0x55055055;
  Varnode *invn = vn->getDef()->getIn(0);
  if (invn->isConstant()) {
    if ((modifiers&GraphSigManager::SIG_DONOTUSE_CONST)==0)
      val ^= vn->getOffset();
    else
      val ^= 0xa0a0a0a0;
  }
  else if (invn->isPersist())
    val ^= 0xd7651ec3;
  hash[0] = val;
  hash[1] = val;
}

/// \param v is the Varnode being overlayed
/// \param modifiers are the settings being used for signature generation
SignatureEntry::SignatureEntry(Varnode *v,uint4 modifiers)

{
  vn = v;
  op = vn->getDef();
  inSize=0;
  flags=0;
  shadow = (SignatureEntry *)0;
  index = -1;

  // Decide on the effective defining op for the given varnode.
  if (op == (const PcodeOp *)0) {
    flags |= SIG_NODE_TERMINAL;
    return;
  }
  startvn = 0;
  inSize = op->numInput();
  switch(op->code()) {
  case CPUI_COPY:
    if (testStandaloneCopy(vn))
      flags |= SIG_NODE_STANDALONE;
    break;
  case CPUI_INDIRECT:
    inSize -= 1;
    if (testStandaloneCopy(vn))
      flags |= SIG_NODE_STANDALONE;
    break;
  case CPUI_MULTIEQUAL:
    flags |= SIG_NODE_COMMUTATIVE;
    break;
  case CPUI_CALL:
    startvn = 1;
    inSize -= 1;
    break;
  case CPUI_CALLIND:
    startvn = 1;
    inSize -= 1;
    break;
  case CPUI_CALLOTHER:
    startvn = 1;
    inSize -= 1;
    break;
  case CPUI_STORE:
    startvn = 1;
    inSize -= 1;
    break;
  case CPUI_LOAD:
    startvn = 1;
    inSize -= 1;
    break;
  case CPUI_INT_LEFT:
  case CPUI_INT_RIGHT:
  case CPUI_INT_SRIGHT:			// For shift
  case CPUI_SUBPIECE:			// and truncation operators
    if (op->getIn(1)->isConstant())	// if the shift/truncation amount is constant
      inSize = 1;			// make sure we don't even hash in the size of the constant
    break;
  case CPUI_CPOOLREF:
    inSize = 0;				// Only hash-in first input
    break;
  default:
    if (op->isCommutative())
      flags |= SIG_NODE_COMMUTATIVE;
    break;
  }
}

/// Used for adding additional virtual nodes in a modified graph.  There is no actual backing Varnode.
/// \param ind is the post-order index to associate with the virtual node
SignatureEntry::SignatureEntry(int4 ind)

{
  vn = (Varnode *)0;
  op = (PcodeOp *)0;
  inSize=0;
  flags=0;
  shadow = (SignatureEntry *)0;
  index = ind;
  startvn = 0;
}

/// A Varnode is a stand-alone COPY if it is defined by a COPY or INDIRECT operation whose
/// input Varnode is either a constant or an input. Additionally the Varnode must not be
/// read directly by other operations in the function.  There currently is a slight exception
/// made for a \e persistent Varnode; it can be read through a single INDIRECT operation.
/// \param vn is the given Varnode to test
/// \return \b true if it is considered a stand-alone COPY
bool SignatureEntry::testStandaloneCopy(Varnode *vn)

{
  PcodeOp *op = vn->getDef();
  const Varnode *invn = op->getIn(0);
  if (invn->isWritten())
    return false;
  if (invn->getAddr() == vn->getAddr())
    return false;

  if (vn->isPersist() && op->code() == CPUI_INDIRECT)
    return true;
  list<PcodeOp *>::const_iterator iter = vn->beginDescend();
  if (iter == vn->endDescend())
    return true;
  PcodeOp *descOp = *iter;
  ++iter;
  if (iter != vn->endDescend())
    return false;
  OpCode opc = descOp->code();
  if (vn->isPersist() && opc == CPUI_INDIRECT) {
    return true;
  }
  // Account for COPY and INDIRECT placeholder conventions
  if (opc != CPUI_COPY && opc != CPUI_INDIRECT)
    return false;
  return descOp->getOut()->hasNoDescend();
}

/// The current hash value is set, incorporating:
///   - the size of the Varnode
///   - whether the Varnode is constant
///   - whether the Varnode is an input
///   - whether the Varnode is persistent
///   - the OpCode of the effective defining PcodeOp
///
/// \param modifiers are the settings being used for signature generation
void SignatureEntry::localHash(uint4 modifiers)

{
  hashword localhash;

  if (vn->isAnnotation()) {
    localhash = 0xb7b7b7b7;		// This mostly won't get used, but in some rare cases
    flags |= (SIG_NODE_NOT_EMITTED | SIG_NODE_TERMINAL);
    hash[0] = localhash;	// Allow terminal node to access value from both slots without moving data in iteration
    hash[1] = localhash;
    return;
  }
  if (shadow != (SignatureEntry *)0) {	// If this is a shadow
      flags |= SIG_NODE_NOT_EMITTED;	// Don't emit as a feature
      if (isStandaloneCopy()) {
	standaloneCopyHash(modifiers);	// Standalone COPY gets special hash
      }
      return;				// Don't calculate hash otherwise
  }

  localhash = hashSize(vn,modifiers);

  if (!vn->isWritten())			// If there isn't at least some tree above this varnode
    flags |= SIG_NODE_NOT_EMITTED;	// Don't emit this hash as a feature, but still generate hash
  hashword ophash = getOpHash(modifiers);

				// Class of varnode
  if (vn->isConstant()) {
    if ((modifiers&GraphSigManager::SIG_DONOTUSE_CONST)==0)
      localhash ^= vn->getOffset();
    else
      localhash ^= 0xa0a0a0a0;
  }
  // Note that internally, a persist storage location may get propagated away
  // so make sure varnode is an input.
  if ((modifiers&GraphSigManager::SIG_DONOTUSE_PERSIST)==0) {
    if (vn->isPersist()&&vn->isInput())
      localhash ^= (hashword) 0x55055055;
  }
//  if ((modifiers&GraphSigManager::SIG_DONOTUSE_INPUT)==0)
  if (vn->isInput())
    localhash ^= (hashword) 0x10101;
  if (ophash != 0) {
    localhash ^= ophash ^ (ophash<<9) ^ (ophash<<18);
  }

  hash[0] = localhash;		// Allow terminal nodes to access value from both slots without moving data in iteration
  hash[1] = localhash;
}

/// The previous hash value for \b this node is mixed together with previous hash values from other given nodes.
/// The result becomes the current hash value for \b this node.
/// \param neigh is the list of given nodes to mix in
void SignatureEntry::hashIn(vector<SignatureEntry *> &neigh)

{
  hashword curhash = hash[1];
  if (isCommutative()) {
    hashword accum = 0;
    hashword tmphash;
    for(int4 i=0;i<neigh.size();++i) {
      SignatureEntry *entry = neigh[i];
      tmphash = hash_mixin(curhash,entry->hash[1]);
      accum += tmphash;
    }
    curhash = hash_mixin(curhash,accum);
  }
  else {
    for(int4 i=0;i<neigh.size();++i) {
      SignatureEntry *entry = neigh[i];
      curhash = hash_mixin(curhash,entry->hash[1]);
    }
  }
  hash[0] = curhash;
}

/// \brief Do a post-ordering of the modified \e noise graph
///
/// The \e noise graph is formed from the original graph by removing all non-marker edges.
/// Root Varnodes for the \e noise graph, which are either inputs or are defined by a non-marker operation
/// in the original graph, must be provided.  The SignatureEntry objects are passed back in post-order, and the
/// post-order index is stored on each object.
/// \param rootlist contains the roots of the graph
/// \param postOrder will hold the array of SignatureEntrys in post-order
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::noisePostOrder(const vector<SignatureEntry *> &rootlist,vector<SignatureEntry *> &postOrder,map<int4,SignatureEntry *> &sigMap)

{
  vector<DFSNode> stack;
  for(int4 i=0;i<rootlist.size();++i) {
    stack.push_back(DFSNode());
    SignatureEntry *entry = rootlist[i];
    stack.back().entry = entry;
    stack.back().iter = entry->vn->beginDescend();
    entry->setVisited();
    while(!stack.empty()) {
      entry = stack.back().entry;
      list<PcodeOp *>::const_iterator iter = stack.back().iter;
      if (iter == entry->vn->endDescend()) {	// No more children to traverse
	stack.pop_back();
	entry->index = postOrder.size();
	postOrder.push_back(entry);
      }
      else {
	PcodeOp *op = *iter;
	stack.back().iter = ++iter;
	if (op->isMarker() || op->code() == CPUI_COPY) {
	  SignatureEntry *childEntry = mapToEntry(op->getOut(),sigMap);
	  if (!childEntry->isVisited()) {
	    childEntry->setVisited();
	    stack.push_back(DFSNode());
	    stack.back().entry = childEntry;
	    stack.back().iter = childEntry->vn->beginDescend();
	  }
	}
      }
    }
  }
}

/// \brief Construct the dominator tree for the modified \e noise graph
///
/// The \e noise graph is formed from the original graph by removing all non-marker edges.
/// Additionally a virtual root links all Varnodes that were inputs or had their defining op removed.
/// After this routine completes, the shadow field of each node is filled in with its immediate dominator
/// relative to the modified \e noise graph.
/// \param postOrder is the list of nodes in the \e noise graph in post-order
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::noiseDominator(vector<SignatureEntry *> &postOrder,map<int4,SignatureEntry *> &sigMap)

{
  SignatureEntry *b,*virtualRoot;
  virtualRoot = b = postOrder.back();		// The official start node
  b->shadow = b;
  bool changed = true;
  SignatureEntry *new_idom = (SignatureEntry *)0;
  while(changed) {
    changed = false;
    for(int4 i=postOrder.size()-2;i>=0;--i) { // For all nodes, in reverse post-order, except root
      b = postOrder[i];
      if (b->shadow != postOrder.back()) {
	int4 j;
	int4 sizeIn = b->markerSizeIn();
	for(j=0;j<sizeIn;++j) { // Find first processed node
	  new_idom = b->getMarkerIn(j,virtualRoot,sigMap);
	  if (new_idom->shadow != (SignatureEntry *)0)
	    break;
	}
	j += 1;
	for(;j<sizeIn;++j) {
	  SignatureEntry *rho = b->getMarkerIn(j,virtualRoot,sigMap);
	  if (rho->shadow != (SignatureEntry *)0) { // Here is the intersection routine
	    int4 finger1 = rho->index;
	    int4 finger2 = new_idom->index;
	    while(finger1 != finger2) {
	      while(finger1 < finger2)
		finger1 = postOrder[finger1]->shadow->index;
	      while(finger2 < finger1)
		finger2 = postOrder[finger2]->shadow->index;
	    }
	    new_idom = postOrder[finger1];
	  }
	}
	if (b->shadow != new_idom) {
	  b->shadow = new_idom;
	  changed = true;
	}
      }
    }
  }
}

/// \brief Remove \e noise from the data-flow graph by collapsing Varnodes that are indirect copies of each other
///
/// Two Varnodes are indirect copies if the only paths from one to the other are made up of:
///   - CPUI_COPY
///   - CPUI_INDIRECT   and
///   - CPUI_MULTIEQUAL
///
/// This routine creates a \e noise (sub-)graph from the data-flow graph by removing all PcodeOp edges
/// that are not one of these three.  A virtual root is created for the \e noise graph connecting all
/// the input Varnodes and Varnodes defined by one of the removed PcodeOps.  The dominator tree
/// is calculated for this rooted \e noise graph.  Any Varnode whose immediate dominator is the virtual root
/// is a \e shadow \e base and is not an indirect copy of any other Varnode.  All other Varnodes are
/// indirect copies of one of these shadow bases, which can be calculated from the dominator tree.
/// Indirectly copied varnodes are collapsed into their shadow base and will have a non-zero \b shadow
/// field pointing to this base.
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::removeNoise(map<int4,SignatureEntry *> &sigMap)

{
  vector<SignatureEntry *> rootlist;
  vector<SignatureEntry *> postOrder;

  // Set up the virtual root, by calculating all the nodes it is connected to into -rootlist-
  map<int4,SignatureEntry *>::const_iterator iter;
  for(iter=sigMap.begin();iter!=sigMap.end();++iter) {
    SignatureEntry *entry = (*iter).second;
    Varnode *vn = entry->vn;
    if (vn->isInput() || vn->isConstant()) {			// Varnode is an input OR
      rootlist.push_back(entry);
      entry->flags |= MARKER_ROOT;
    }
    else if (vn->isWritten()) {
      PcodeOp *op = vn->getDef();
      if ((!op->isMarker()) && op->code() != CPUI_COPY) {	// Varnode is defined by a non-marker
	rootlist.push_back(entry);
	entry->flags |= MARKER_ROOT;
      }
    }
  }

  noisePostOrder(rootlist,postOrder,sigMap);
  // To get a proper unique root for the dominator algorithm,
  //    we construct a virtual root with out edges to every node in -rootlilst-
  // -postOrder- is the list of nodes already in forward post-order
  SignatureEntry virtualRoot(postOrder.size());
  postOrder.push_back(&virtualRoot);
  for(int4 i=0;i<rootlist.size();++i)	// Fill in dom of nodes which start immediately
    rootlist[i]->shadow = &virtualRoot;	// connects to (to deal with possible artificial edge)

  noiseDominator(postOrder,sigMap);
  postOrder.pop_back();			// Pop off virtual root

  // Calculate the shadow bases and set their -shadow- field to null
  for(int4 i=0;i<postOrder.size();++i) {
    SignatureEntry *entry = postOrder[i];
    if (entry->shadow == &virtualRoot)
      entry->shadow = (SignatureEntry *)0;
  }
  // Set the final shadow field by collapsing the dominator tree to the shadow bases
  for(int4 i=0;i<postOrder.size();++i) {
    SignatureEntry *entry = postOrder[i];
    SignatureEntry *base = entry;
    while(base->shadow != (SignatureEntry *)0) {
      base = base->shadow;
    }
    while(entry->shadow != (SignatureEntry *)0) {
      SignatureEntry *tmp = entry;
      entry = entry->shadow;
      tmp->shadow = base;
    }
  }
}

#ifdef COPYNOISE_DEBUG
/// Check if \b this should have a \b shadow or not.
/// If so, make sure all inputs to \b this share the same shadow.
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::verifyNoiseRemoval(map<int4,SignatureEntry *> &sigMap) const

{
  if (shadow == (SignatureEntry *)0) {
    if (!vn->isWritten()) return;
    PcodeOp *op = vn->getDef();
    OpCode opc = op->code();
    if (opc == CPUI_COPY || opc == CPUI_INDIRECT)
      throw LowlevelError("Node should be shadowed but isnt");
    return;
  }
  if (!vn->isWritten())
    throw LowlevelError("Shadowed node has no input");
  PcodeOp *op = vn->getDef();
  OpCode opc = op->code();
  if (opc == CPUI_COPY || opc == CPUI_INDIRECT) {
    Varnode *invn = op->getIn(0);
    SignatureEntry *inEntry = sigMap[invn->getCreateIndex()];
    if (inEntry->shadow == (SignatureEntry *)0) {	// Terminal point of COPY chain
      if (shadow != inEntry)
	throw LowlevelError("Shadow does not match terminator");
    }
    else if (inEntry->shadow != shadow)
      throw LowlevelError("Shadow mismatch between varnode and COPY/INDIRECT input");
  }
  else if (opc == CPUI_MULTIEQUAL) {
    for(int4 i=0;i<op->numInput();++i) {
      Varnode *invn = op->getIn(i);
      SignatureEntry *inEntry = sigMap[invn->getCreateIndex()];
      if (inEntry->shadow == (SignatureEntry *)0) {	// Terminal point of COPY chain
        if (shadow != inEntry)
  	throw LowlevelError("Shadow does not match multi terminator");
      }
      else if (inEntry->shadow != shadow)
        throw LowlevelError("Shadow mismatch between varnode and MULTIEQUAL input");
    }
  }
  else
    throw LowlevelError("Shadowing varnode not written by COPY/INDIRECT/MULTIEQUAL");
}

/// Run through all SignatureEntry in the map.
/// \param sigMap is the map from Varnode to its SignatureEntry overlay
void SignatureEntry::verifyAllNoiseRemoval(map<int4,SignatureEntry *> &sigMap)

{
  map<int4,SignatureEntry *>::const_iterator iter;
  for(iter=sigMap.begin();iter!=sigMap.end();++iter) {
    (*iter).second->verifyNoiseRemoval(sigMap);
  }
}
#endif

/// The current hash value is set, incorporating the number of incoming edges and the number of outgoing
/// edges, as integer values.
/// \param modifiers are the settings being used for signature generation
void BlockSignatureEntry::localHash(uint4 modifiers)

{
  hashword localhash = bl->sizeIn();
  localhash <<= 8;
  localhash |= bl->sizeOut();
  hash[0] = localhash;
}

/// The previous hash value for \b this node is mixed together with previous hash values from other given nodes.
/// The result becomes the current hash value for \b this node.
/// The given nodes \e must correspond one-to-one with incoming blocks of \b this.
/// \param neigh is the list of nodes coming in to \b this
void BlockSignatureEntry::hashIn(vector<BlockSignatureEntry *> &neigh)

{
  hashword curhash = hash[1];
  hashword accum = 0xbafabaca;
  hashword tmphash;
  for(int4 i=0;i<neigh.size();++i) { // Make hash invariant on order of input blocks
    BlockSignatureEntry *entry = neigh[i];
    tmphash = hash_mixin(curhash,entry->hash[1] );
    if (entry->bl->sizeOut() == 2) {		// If the incoming block ends in a CBRANCH
      if (bl->getInRevIndex(i) == 0)
	tmphash = hash_mixin(tmphash,0x777 ^ 0x7abc7abc);	// Incoming edge on FALSE condition
      else
	tmphash = hash_mixin(tmphash,0x777);	// Incoming edge on TRUE condition
    }
    accum += tmphash;
  }
  hash[0] = hash_mixin(curhash,accum);
}

/// The hash value is encoded to the stream, along with any descriptive information about
/// how the feature was formed.
/// \param encoder is the stream encoder
void Signature::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_GENSIG);
  encoder.writeUnsignedInteger(ATTRIB_HASH, getHash());
  encoder.closeElement(ELEM_GENSIG);
}

/// The hash value corresponding to \b this feature is read from the stream.
/// \param decoder is the stream decoder
void Signature::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement(ELEM_GENSIG);
  sig = decoder.readUnsignedInteger(ATTRIB_HASH);
  decoder.closeElement(elemId);
}

void VarnodeSignature::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_VARSIG);
  encoder.writeUnsignedInteger(ATTRIB_HASH, getHash());
  vn->encode(encoder);
  if (vn->isWritten())
    vn->getDef()->encode(encoder);
  encoder.closeElement(ELEM_VARSIG);
}

void BlockSignature::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_BLOCKSIG);
  encoder.writeUnsignedInteger(ATTRIB_HASH, getHash());
  encoder.writeSignedInteger(ATTRIB_INDEX, bl->getIndex());
  bl->getStart().encode(encoder);
  if (op2 != (const PcodeOp *)0)
    op2->encode(encoder);
  if (op1 != (const PcodeOp *)0)
    op1->encode(encoder);
  encoder.closeElement(ELEM_BLOCKSIG);
}

void CopySignature::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_COPYSIG);
  encoder.writeUnsignedInteger(ATTRIB_HASH, getHash());
  encoder.writeSignedInteger(ATTRIB_INDEX, bl->getIndex());
  encoder.closeElement(ELEM_COPYSIG);
}

void CopySignature::printOrigin(ostream &s) const

{
  s << "Copies in ";
  bl->printHeader(s);
}

/// Clear any Signature objects specifically
void SigManager::clearSignatures(void)

{
  for(int4 i=0;i<sigs.size();++i)
    delete sigs[i];
  sigs.clear();
}

/// Clear all resources consumed by the manager, including Signature objects and other resources
/// used for generating features. The manager is ready for another round of signature generation.
void SigManager::clear(void)

{
  clearSignatures();
}

/// \param f is the function being set
void SigManager::setCurrentFunction(const Funcdata *f)

{
  fd = f;
}

/// The hash value associated with any features currently held by the manager
/// are written to the provided container.  The hash values are sorted.
/// \param feature will contain the collected hash values
void SigManager::getSignatureVector(vector<uint4> &feature) const

{
  feature.resize(sigs.size(),0);
  for(uint4 i=0;i<sigs.size();++i)
    feature[i] = sigs[i]->getHash();
  sort(feature.begin(),feature.end());
}

/// \return the overall hash value
hashword SigManager::getOverallHash(void) const

{
  vector<uint4> feature;
  getSignatureVector(feature);
  hashword pool = 0x12349876abacab;
  for(uint4 i=0;i<feature.size();++i)
    pool = hash_mixin(pool,feature[i]);
  return pool;
}

/// A brief description of each feature and the hash value itself are printed to the
/// stream, one feature per line.
/// \param s is the character stream to write to
void SigManager::print(ostream &s) const

{
  vector<Signature *>::const_iterator iter;
  for(iter=sigs.begin();iter!=sigs.end();++iter)
    (*iter)->print(s);
}

/// Full details about all features currently stored in \b this manager are written to the stream.
/// \param encoder is the stream encoder
void SigManager::encode(Encoder &encoder) const

{
  encoder.openElement(ELEM_SIGNATUREDESC);
  vector<Signature *>::const_iterator iter;
  for(iter=sigs.begin();iter!=sigs.end();++iter)
    (*iter)->encode(encoder);
  encoder.closeElement(ELEM_SIGNATUREDESC);
}

/// \param newvalue are the settings to be used
void SigManager::setSettings(uint4 newvalue)

{
  settings = newvalue;
}

/// The (previously computed) final hash value for all Varnodes are emitted as VarnodeSignature features.
void GraphSigManager::collectVarnodeSigs(void)

{
  SignatureEntry *entry;
  Signature *vsig;

  map<int4,SignatureEntry *>::const_iterator iter;
  for(iter=sigmap.begin();iter!=sigmap.end();++iter) {
    entry = (*iter).second;
    if (entry->isNotEmitted()) continue;
    vsig = new VarnodeSignature(entry->getVarnode(),entry->getHash());
    addSignature(vsig);
  }
}

/// For each basic block, we scan for operations that represent the roots of expressions:
/// CALL, CALLIND, CALLOTHER, STORE, CBRANCH, BRANCHIND, and RETURN.  These are taken in sequence, as overlapping pairs,
/// generating cross-expression features.  If there are stand-alone COPYs in the basic block, these are combined into
/// a single feature that is invariant under reordering of the COPYs.  Finally a feature is generated that contains
/// pure control-flow information about the basic block.
void GraphSigManager::collectBlockSigs(void)

{
  map<int4,BlockSignatureEntry *>::const_iterator iter;
  for(iter=blockmap.begin();iter!=blockmap.end();++iter) {
    BlockSignatureEntry *entry = (*iter).second;
    BlockBasic *bl = entry->getBlock();

    PcodeOp *op,*lastop;
    SignatureEntry *outEntry;
    hashword lasthash;
    hashword val,callhash,copyhash,finalhash;

    lastop = (PcodeOp *)0;
    lasthash = 0;
    callhash = 0;
    copyhash = 0;
    list<PcodeOp *>::const_iterator oiter,enditer;
    oiter = bl->beginOp();
    enditer = bl->endOp();
    while(oiter != enditer) {
      op = *oiter;
      ++oiter;
      int4 startind = 0;
      int4 stopind = 0;
      switch(op->code()) {
      case CPUI_CALL:
	// We don't care if the output is used or not, always include
	callhash += 100001;
	callhash *= 0x78abbf;
	startind = 1;
	stopind = op->numInput();
	break;
      case CPUI_CALLIND:
	// We don't care if the output is used or not, always include
	callhash += 123451;		// Slightly different than CPUI_CALL
	callhash *= 0x78abbf;
	startind = 1;
	stopind = op->numInput();
	break;
      case CPUI_CALLOTHER:
	// We don't care if the output is used or not, always include
	startind = 1;
	stopind = op->numInput();
	break;
      case CPUI_STORE:
	startind = 1;
	stopind = op->numInput();
	break;
      case CPUI_CBRANCH:
	startind = 1;
	stopind = 2;
	break;
      case CPUI_BRANCHIND:
	startind = 0;
	stopind = 1;
	break;
      case CPUI_RETURN:
	startind = 1;
	stopind = op->numInput();
	break;
      case CPUI_INDIRECT:
      case CPUI_COPY:
	outEntry = SignatureEntry::mapToEntry(op->getOut(), sigmap);
	if (outEntry->isStandaloneCopy()) {
	  copyhash += outEntry->getHash();
	}
	continue;
      default:
	startind = 0;		// Don't use
	stopind = 0;
	break;
      }
      Varnode *outvn = op->getOut();
      if ((stopind == 0) && (outvn == (Varnode *)0 || !outvn->hasNoDescend())) continue;
      if (outvn != (Varnode *) 0) {
	outEntry = SignatureEntry::mapToEntry(outvn, sigmap);
	if (outEntry->isNotEmitted()) continue;
	val = outEntry->getHash();
      }
      else {
	val = (hashword) op->code();
	val = val ^ (val << 9) ^ (val << 18);
	hashword accum = 0;
	for (int4 i = startind; i < stopind; ++i) { // Let hash be invariant under commutivity
	  Varnode *vn = op->getIn(i);
	  hashword tmphash = hash_mixin(val, SignatureEntry::mapToEntryCollapse(vn, sigmap)->getHash());
	  accum += tmphash;
	}
	val ^= accum;		// Even if no-inputs we still get hash of opcode
      }
      if (lastop == (PcodeOp *) 0)
	finalhash = hash_mixin(val, entry->getHash());
      else
	finalhash = hash_mixin(val, lasthash);
      Signature *bsig = new BlockSignature(bl, finalhash, lastop, op);
      addSignature(bsig);
      lastop = op;
      lasthash = val;
    }
    finalhash = hash_mixin(entry->getHash(),0x9b1c5f);		// Create a hash with just block information
    if (callhash != 0)
      finalhash = hash_mixin(finalhash,callhash);
    addSignature(new BlockSignature(bl,finalhash,(PcodeOp *)0,(PcodeOp *)0));
    if (copyhash != 0) {
      copyhash = hash_mixin(copyhash, 0xa2de3c);
      addSignature(new CopySignature(bl,copyhash));
    }
  }
}

void GraphSigManager::varnodeClear(void)

{
  map<int4,SignatureEntry *>::iterator iter;

  for(iter=sigmap.begin();iter!=sigmap.end();++iter)
    delete (*iter).second;

  sigmap.clear();
}

void GraphSigManager::blockClear(void)

{
  map<int4,BlockSignatureEntry *>::iterator iter;

  for(iter=blockmap.begin();iter!=blockmap.end();++iter)
    delete (*iter).second;
  blockmap.clear();
}

/// Every basic block in the current function is allocated a BlockSignatureEntry and
/// local hash information is calculation in preparation for iterating.
void GraphSigManager::initializeBlocks(void)

{
  const BlockGraph &blockgraph(fd->getBasicBlocks());
  for(int4 i=0;i<blockgraph.getSize();++i) {
    BlockBasic *bl = (BlockBasic *)blockgraph.getBlock(i);
    BlockSignatureEntry *entry = new BlockSignatureEntry(bl);
    blockmap[ bl->getIndex() ] = entry;
    entry->localHash(sigmods);
  }
}

/// \return \b true if the settings are valid for \b this manager
bool GraphSigManager::testSettings(uint4 val)

{
  if (val == 0)
    return false;		// 0 setting is not allowed
  // Allowed setting bits
  uint4 mask = SIG_COLLAPSE_SIZE | SIG_DONOTUSE_CONST | SIG_DONOTUSE_INPUT |
      SIG_DONOTUSE_PERSIST | SIG_COLLAPSE_INDNOISE;
  mask = (mask << 2) | 1;		// Add the check bit
  return ((val & ~mask) == 0);		// Do not allow any other bit to be set
}

GraphSigManager::GraphSigManager(void) : SigManager()

{
  // Set reasonable defaults
  uint4 setting = SigManager::getSettings();
  if (!testSettings(setting))
    throw LowlevelError("Bad signature settings");
  sigmods = setting >> 2;
  maxiter = 3;
  maxblockiter = 1;
  maxvarnode = 0;
}

void GraphSigManager::clear(void)

{
  varnodeClear();
  blockClear();
  SigManager::clear();
}

void GraphSigManager::initializeFromStream(istream &s)

{
  int4 mymaxiter;

  s.unsetf(ios::dec | ios::hex | ios::oct); // Let user specify base
  mymaxiter = -1;
  s >> ws >> mymaxiter;

  if (mymaxiter!=-1)
    maxiter = mymaxiter;
}

void GraphSigManager::setCurrentFunction(const Funcdata *f)

{
  SigManager::setCurrentFunction(f);

  VarnodeLocSet::const_iterator iter;
  int4 size = f->numVarnodes();
  if ((maxvarnode!=0)&&(size > maxvarnode))
    throw LowlevelError(f->getName() + " exceeds size threshold for generating signatures");

  for(iter=f->beginLoc();iter!=f->endLoc();++iter) {
    Varnode *vn = *iter;
    SignatureEntry *entry = new SignatureEntry(vn,sigmods);
    sigmap[ vn->getCreateIndex() ] = entry;
  }
  map<int4,SignatureEntry *>::const_iterator sigiter;
  if ((sigmods & SIG_COLLAPSE_INDNOISE)!=0) {
    SignatureEntry::removeNoise(sigmap);
#ifdef COPYNOISE_DEBUG
    SignatureEntry::verifyAllNoiseRemoval(sigmap);
#endif
  }
  else {
    for(sigiter=sigmap.begin();sigiter!=sigmap.end();++sigiter)
      (*sigiter).second->calculateShadow(sigmap);
  }
  for(sigiter=sigmap.begin();sigiter!=sigmap.end();++sigiter) {
    SignatureEntry *entry = (*sigiter).second;
    entry->localHash(sigmods);
  }
}

void GraphSigManager::flipVarnodes(void)

{
  map<int4,SignatureEntry *>::iterator iter;
  
  for(iter=sigmap.begin();iter!=sigmap.end();++iter) {
    SignatureEntry *entry = (*iter).second;
    entry->flip();
  }
}

void GraphSigManager::flipBlocks(void)

{
  map<int4,BlockSignatureEntry *>::iterator iter;

  for(iter=blockmap.begin();iter!=blockmap.end();++iter) {
    BlockSignatureEntry *entry = (*iter).second;
    entry->flip();
  }
}

/// Run through every Varnode (via its SignatureEntry overlay) and combine its current hash value
/// with the current hash value of the Varnode inputs to its effective defining PcodeOp.
void GraphSigManager::signatureIterate(void)

{
  int4 j;
  SignatureEntry *entry,*vnentry;
  vector<SignatureEntry *> neigh;
  map<int4,SignatureEntry *>::const_iterator iter;

  flipVarnodes();
  for(iter=sigmap.begin();iter!=sigmap.end();++iter) {
    entry = (*iter).second;
    if (entry->isNotEmitted()) continue;
    if (entry->isTerminal()) continue;
    int4 num = entry->numInputs();
    neigh.clear();
    for(j=0;j<num;++j) {
      vnentry = entry->getIn(j,sigmap);
      neigh.push_back(vnentry);
    }
    entry->hashIn(neigh);
  }
}

/// Run through every basic block (via its BlockSignatureEntry overlay) and combine its current hash value
/// with the current hash value of the incoming basic blocks.
void GraphSigManager::signatureBlockIterate(void)

{
  vector<BlockSignatureEntry *> neigh;

  flipBlocks();
  map<int4,BlockSignatureEntry *>::const_iterator iter,biter;

  for(iter=blockmap.begin();iter!=blockmap.end();++iter) {
    BlockSignatureEntry *entry = (*iter).second;
    BlockBasic *bl = entry->getBlock();
    neigh.clear();
    for(int4 i=0;i<bl->sizeIn();++i) {
      FlowBlock *inbl = bl->getIn(i);
      biter = blockmap.find(inbl->getIndex());
      BlockSignatureEntry *inentry = (*biter).second;
      neigh.push_back(inentry);
    }
    entry->hashIn(neigh);
  }
}

void GraphSigManager::generate(void)

{
  int4 minusone,firsthalf,secondhalf;

  minusone = maxiter - 1;
  firsthalf = minusone/2;
  secondhalf = minusone - firsthalf;
  signatureIterate();
  for(int4 i=0;i<firsthalf;++i)
    signatureIterate();

  // Do the block signatures incorporating varnode sigs halfway thru
  if (maxblockiter >=0 ) {
    initializeBlocks();
    for(int4 i=0;i<maxblockiter;++i) {
      signatureBlockIterate();
    }
    collectBlockSigs();
    blockClear();
  }

  for(int4 i=0;i<secondhalf;++i)
    signatureIterate();

  collectVarnodeSigs();

  varnodeClear();		// Varnodes are used in block sigs
}

/// Features are generated for the function and written to the encoder as a simple sequence of hash values.
/// No additional information about the features is written to the encoder.
/// The function must have been previously decompiled.  If function decompilation failed due to either: flow
/// into bad data or unimplemented instructions, an error condition is encoded to the stream.
/// \param fd is the function to extract features from
/// \param encoder is the stream encoder to write output to
void simpleSignature(Funcdata *fd,Encoder &encoder)

{
  GraphSigManager sigmanager;

  //  sigmanager.setMaxVarnode(100000);
  sigmanager.setCurrentFunction(fd);
  sigmanager.generate();
  vector<uint4> feature;
  sigmanager.getSignatureVector(feature);
  encoder.openElement(ELEM_SIGNATURES);
  if (fd->hasUnimplemented())
    encoder.writeBool(ATTRIB_UNIMPL, true);
  if (fd->hasBadData())
    encoder.writeBool(ATTRIB_BADDATA, true);
  for(uint4 i=0;i<feature.size();++i) {
    encoder.openElement(ELEM_SIG);
    encoder.writeUnsignedInteger(ATTRIB_VAL, feature[i]);
    encoder.closeElement(ELEM_SIG);
  }
  uint4 numcalls = fd->numCalls();
  for(uint4 i=0;i<numcalls;++i) {
    FuncCallSpecs *fc = fd->getCallSpecs(i);
    const Address &addr(fc->getEntryAddress());
    if (!addr.isInvalid()) {
      encoder.openElement(ELEM_CALL);
      encoder.writeSpace(ATTRIB_SPACE, addr.getSpace());
      encoder.writeUnsignedInteger(ATTRIB_OFFSET, addr.getOffset());
      encoder.closeElement(ELEM_CALL);
    }
  }
  encoder.closeElement(ELEM_SIGNATURES);
}

/// Features are generated for the function and a complete description of each feature is
/// written to the encoder. The function must have been previously decompiled.
/// \param fd is the function to extract features from
/// \param encoder is the stream encoder to write output to
void debugSignature(Funcdata *fd,Encoder &encoder)

{
  GraphSigManager sigmanager;

  sigmanager.setCurrentFunction(fd);
  sigmanager.generate();
  sigmanager.sortByHash();
  sigmanager.encode(encoder);
}

} // End namespace ghidra
