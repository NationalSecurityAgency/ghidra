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
/// \file signature.hh
/// \brief Classes for generating feature vectors representing individual functions
#ifndef __SIGNATURE_HH__
#define __SIGNATURE_HH__

#include "funcdata.hh"

namespace ghidra {

typedef uint8 hashword;			///< Data-type for containing hash information

extern AttributeId ATTRIB_BADDATA;	///< Marshaling attribute "baddata"
extern AttributeId ATTRIB_HASH;		///< Marshaling attribute "hash"
extern AttributeId ATTRIB_UNIMPL;	///< Marshaling attribute "unimpl"

extern ElementId ELEM_BLOCKSIG;		///< Marshaling element \<blocksig>
extern ElementId ELEM_CALL;		///< Marshaling element \<call>
extern ElementId ELEM_GENSIG;		///< Marshaling element \<gensig>
extern ElementId ELEM_MAJOR;		///< Marshaling element \<major>
extern ElementId ELEM_MINOR;		///< Marshaling element \<minor>
extern ElementId ELEM_COPYSIG;		///< Marshaling element \<copysig>
extern ElementId ELEM_SETTINGS;		///< Marshaling element \<settings>
extern ElementId ELEM_SIG;		///< Marshaling element \<sig>
extern ElementId ELEM_SIGNATUREDESC;	///< Marshaling element \<signaturedesc>
extern ElementId ELEM_SIGNATURES;	///< Marshaling element \<signatures>
extern ElementId ELEM_SIGSETTINGS;	///< Marshaling element \<sigsettings>
extern ElementId ELEM_VARSIG;		///< Marshaling element \<varsig>

/// \brief A \b feature describing some aspect of a function or other unit of code
///
/// The underlying representation is just a 32-bit hash of the \e information representing
/// the feature, but derived classes may be contain other meta-data describing where and how the
/// feature was formed. Two features are generally unordered (they are either equal or not equal),
/// but an ordering is used internally to normalize the vector representation and accelerate comparison.
class Signature {
  uint4 sig;					///< Underlying 32-bit hash
public:
  Signature(hashword h) { sig=(uint4)h; }	///< Constructor
  uint4 getHash(void) const { return sig; }	///< Get the underyling 32-bit hash of the feature
  void print(ostream &s) const;			///< Print the feature hash and a brief description of \b this feature to the given stream
  int4 compare(const Signature *op2) const;	///< Compare two features
  virtual ~Signature(void) {}			///< Destructor
  virtual void encode(Encoder &encoder) const;	/// Encode \b this feature to the given stream
  virtual void decode(Decoder &decoder);	/// Restore \b this feature from the given stream

  /// \brief Print a brief description of \b this feature to the given stream
  virtual void printOrigin(ostream &s) const {
    s << hex << "0x" << setfill('0') << setw(8) << sig;
  }

  /// \brief Compare two Signature pointers via their underlying hash values
  static bool comparePtr(Signature *a,Signature *b) { return (a->sig < b->sig); }
};

/// \brief A node for data-flow \b feature generation
///
/// A SignatureEntry is rooted at a specific Varnode in the data-flow of a function.
/// During feature generation it iteratively hashes information about the Varnode and its nearest
/// neighbors through the edges of the graph.  Feature generation needs to explicitly label:
///   - Varnodes that don't contribute meaningful information
///   - Shadow Varnodes that are direct or indirect COPYs of other Varnodes
///   - Stand-alone COPYs from a constant or input to a Varnode that is not directly read from again
class SignatureEntry {
  /// Varnode properties that need to be explicit during feature generation
  enum SignatureFlags {
    SIG_NODE_TERMINAL = 0x1,	///< Varnode has no incoming edges
    SIG_NODE_COMMUTATIVE = 0x2,	///< No distinction between this Varnode's incoming edges
    SIG_NODE_NOT_EMITTED = 0x4,	///< Varnode is not emitted as a formal feature (it might be hashed with other features)
    SIG_NODE_STANDALONE = 0x8,	///< Varnode is a stand-alone COPY
    VISITED = 0x10,		///< Mark for spanning tree construction
    MARKER_ROOT = 0x20		///< Special root status in marker subgraph
  };
  /// \brief A path node for doing depth first traversals of data-flow informed by SignatureEntry
  struct DFSNode {
    SignatureEntry *entry;			///< The specific node in the traversal path
    list<PcodeOp *>::const_iterator iter;	///< The edge to the next node in the path
  };
  Varnode *vn;				///< The root Varnode
  uint4 flags;				///< Feature generation properties of this Varnode
  hashword hash[2];			///< Current and previous hash
  const PcodeOp *op;			///< The \e effective defining PcodeOp of this Varnode
  int4 startvn;				///< First incoming edge (via the \e effective PcodeOp)
  int4 inSize;				///< Number of incoming edges
  int4 index;				///< Post-order index
  SignatureEntry *shadow;		///< (If non-null) the Varnode being \e shadowed by this
  hashword getOpHash(uint4 modifiers);	///< Get a hash encoding the OpCode of the \e effective defining PcodeOp
  bool isVisited(void) const { return ((flags&VISITED)!=0); }	///< Return \b true if \b this node has been visited before
  void setVisited(void) { flags |= VISITED; }	///< Mark that \b this node has been visited

  /// \brief Get the number of input edges for \b this in the noise reduced form of the data-flow graph
  ///
  /// \return the number of input edges
  int4 markerSizeIn(void) const {
    if ((flags&MARKER_ROOT)!=0) return 1;
    return numInputs();
  }

  /// \brief Get a specific node coming into \b this in the noise reduced form of the data-flow graph
  ///
  /// \param i is the index of the incoming node
  /// \param vRoot is the virtual root of the noise reduced form
  /// \param sigMap is the map from a Varnode to its SignatureEntry overlay
  /// \return the incoming SignatureEntry
  SignatureEntry *getMarkerIn(int4 i,SignatureEntry *vRoot,const map<int4,SignatureEntry *> &sigMap) const {
    if ((flags&MARKER_ROOT)!=0) return vRoot;
    return mapToEntry(op->getIn(i+startvn),sigMap);
  }

  void standaloneCopyHash(uint4 modifiers);		///< Calculate the hash for stand-alone COPY
  static bool testStandaloneCopy(Varnode *vn);		///< Determine if the given Varnode is a stand-alone COPY
  static void noisePostOrder(const vector<SignatureEntry *> &rootlist,vector<SignatureEntry *> &postOrder,map<int4,SignatureEntry *> &sigMap);
  static void noiseDominator(vector<SignatureEntry *> &postOrder,map<int4,SignatureEntry *> &sigMap);
public:
  SignatureEntry(Varnode *v,uint4 modifiers);		///< Construct from a Varnode
  SignatureEntry(int4 ind);				///< Construct a virtual node
  bool isTerminal(void) const { return ((flags&SIG_NODE_TERMINAL)!=0); }	///< Return \b true if \b this node has no inputs
  bool isNotEmitted(void) const { return ((flags&SIG_NODE_NOT_EMITTED)!=0); }	///< Return \b true if \b this is not emitted as a feature
  bool isCommutative(void) const { return ((flags&SIG_NODE_COMMUTATIVE)!=0); }	///< Return \b true if inputs to \b this are unordered
  bool isStandaloneCopy(void) const { return ((flags&SIG_NODE_STANDALONE)!=0); }	///< Return \b true if \b this is a stand-alone COPY
  int4 numInputs(void) const { return inSize; }		///< Return the number incoming edges to \b this node

  /// \brief Get the i-th incoming node
  ///
  /// \param i is the index
  /// \param sigMap is the map from Varnode to its SignatureEntry overlay
  /// \return the selected incoming SignatureEntry node
  SignatureEntry *getIn(int4 i,const map<int4,SignatureEntry *> &sigMap) const {
    return mapToEntryCollapse(op->getIn(i+startvn),sigMap);
  }

  void calculateShadow(const map<int4,SignatureEntry *> &sigMap);	///< Determine if \b this node shadows another
  void localHash(uint4 modifiers);			///< Compute an initial hash based on local properties of the Varnode
  void flip(void) { hash[1] = hash[0]; }		///< Store hash from previous iteration and prepare for next iteration
  void hashIn(vector<SignatureEntry *> &neigh);		///< Hash info from other nodes into \b this
  Varnode *getVarnode(void) const { return vn; }	///< Get the underlying Varnode which \b this overlays
  hashword getHash(void) const { return hash[0]; }	///< Get the current hash value
  static SignatureEntry *mapToEntry(const Varnode *vn,const map<int4,SignatureEntry *> &sigMap);
  static SignatureEntry *mapToEntryCollapse(const Varnode *vn,const map<int4,SignatureEntry *> &sigMap);
  static void removeNoise(map<int4,SignatureEntry *> &sigMap);
  static hashword hashSize(Varnode *vn,uint4 modifiers);
#ifdef COPYNOISE_DEBUG
  void verifyNoiseRemoval(map<int4,SignatureEntry *> &sigMap) const;		///< Verify \b shadow is set correctly for \b this
  static void verifyAllNoiseRemoval(map<int4,SignatureEntry *> &sigMap);	///< Verify all nodes have \b shadow set correctly
#endif
};

/// \brief A node for control-flow feature generation
///
/// A BlockSignatureEntry is rooted at a specific basic block in the control-flow of a function.
/// During feature generation it iteratively hashes information about the basic block and its
/// nearest neighbors through the edges of the control-flow graph.
class BlockSignatureEntry {
  BlockBasic *bl;		///< The root basic block
  hashword hash[2];		///< Current and previous hash
public:
  BlockSignatureEntry(BlockBasic *b) { bl = b; }	///< Construct from a basic block
  void localHash(uint4 modifiers);			///< Compute an initial hash based on local properties of the basic block
  void flip(void) { hash[1] = hash[0]; }		///< Store hash from previous iteration and prepare for next iteration
  void hashIn(vector<BlockSignatureEntry *> &neigh);	///< Hash info from other nodes into \b this
  BlockBasic *getBlock(void) const { return bl; }	///< Get the underlying basic block which \b this overlays
  hashword getHash(void) const { return hash[0]; }	///< Get the current hash value
};

/// \brief A \e feature representing a portion of the data-flow graph rooted at a particular Varnode
///
/// The feature recursively incorporates details about the Varnode, the PcodeOp that defined it and
/// its input Varnodes, up to a specific depth.
class VarnodeSignature : public Signature {
  const Varnode *vn;		///< The root Varnode
public:
  VarnodeSignature(const Varnode *v,hashword h) : Signature(h) { vn = v; }	///< Constructor
  virtual void encode(Encoder &encoder) const;
  virtual void printOrigin(ostream &s) const { vn->printRaw(s); }
};

/// \brief A \e feature rooted in a basic block
///
/// There are two forms of a block feature.
/// Form 1 contains only local control-flow information about the basic block.
/// Form 2 is a feature that combines two operations that occur in sequence within the block.
/// This form incorporates info about the operations and data-flow info about their inputs.
class BlockSignature : public Signature {
  const BlockBasic *bl;		///< The root basic block
  const PcodeOp *op1;		///< (Form 2)The first operation in sequence in the feature
  const PcodeOp *op2;		///< (Form 2)The second operation in sequence in the feature
public:
  BlockSignature(const BlockBasic *b,hashword h,
		 const PcodeOp *o1,const PcodeOp *o2) : Signature(h)
  { bl = b; op1 = o1; op2 = o2; }	///< Constructor
  virtual void encode(Encoder &encoder) const;
  virtual void printOrigin(ostream &s) const { bl->printHeader(s); }
};

/// \brief A feature representing 1 or more \e stand-alone copies in a basic block
///
/// A COPY operation is considered stand-alone if either a constant or a function input
/// is copied into a location that is then not read directly by the function.
/// These COPYs are incorporated into a single feature, which encodes the number
/// and type of COPYs but does not encode the order in which they occur within the block.
class CopySignature : public Signature {
  const BlockBasic *bl;		///< The basic block containing the COPY
public:
  CopySignature(const BlockBasic *b,hashword h)
    : Signature(h) { bl = b; }	///< Constructor
  virtual void encode(Encoder &encoder) const;
  virtual void printOrigin(ostream &s) const;
};

/// \brief A container for collecting a set of features (a feature vector) for a single function
///
/// This manager handles:
///   - Configuring details of the signature generation process
///   - Establishing the function being signatured , via setCurrentFunction()
///   - Generating the features, via generate()
///   - Outputting the features, via encode() or print()
///
/// The manager can be reused for multiple functions.
class SigManager {
  static uint4 settings;		///< Signature settings (across all managers)
  vector<Signature *> sigs;		///< Feature set for the current function
  void clearSignatures(void);		///< Clear all current Signature/feature objects from \b this manager
protected:
  const Funcdata *fd;			///< Current function off of which we are generating features
  void addSignature(Signature *sig) { sigs.push_back(sig); }	///< Add a new feature to the manager
public:
  SigManager(void) { fd = (const Funcdata *)0; }	///< Constructor
  virtual ~SigManager(void) { clearSignatures(); }	///< Destructor
  virtual void clear(void);				///< Clear all current Signature/feature resources
  virtual void initializeFromStream(istream &s)=0;	///< Read configuration information from a character stream
  virtual void setCurrentFunction(const Funcdata *f);	///< Set the function used for (future) feature generation
  virtual void generate(void)=0;			///< Generate all features for the current function
  int4 numSignatures(void) const { return sigs.size(); }	///< Get the number of features currently generated
  Signature *getSignature(int4 i) const { return sigs[i]; }	///< Get the i-th Signature/feature
  void getSignatureVector(vector<uint4> &feature) const;	///< Get the feature vector as a simple array of hashes
  hashword getOverallHash(void) const;			///< Combine all feature hashes into one overall hash
  void sortByHash(void) { sort(sigs.begin(),sigs.end(),Signature::comparePtr); }	///< Sort all current features
  void print(ostream &s) const;				///< Print a brief description of all current features to a stream
  void encode(Encoder &encoder) const;			///< Encode all current features to the given stream
  static uint4 getSettings(void) { return settings; }	///< Get the settings currently being used for signature generation
  static void setSettings(uint4 newvalue);		///< Establish settings to use for future signature generation
};

/// \brief A manager for generating Signatures/features on function data-flow and control-flow
///
/// Features are extracted from the data-flow and control-flow graphs of the function.
/// The different feature types produced by this manager are:
///   - VarnodeSignature
///   - BlockSignature
///   - CopySignature
class GraphSigManager : public SigManager {
public:
  /// Signature generation settings
  enum Mods {
    SIG_COLLAPSE_SIZE = 0x1,     	///< Treat certain varnode sizes as the same
    SIG_COLLAPSE_INDNOISE = 0x2,	///< Collapse varnodes that indirect copies of each other
//    SIG_CALL_TERMINAL = 0x8,  	///< Do not consider data-flow across CALLs
    SIG_DONOTUSE_CONST = 0x10,		///< Do not use value of constant in hash
    SIG_DONOTUSE_INPUT = 0x20,		///< Do not use (fact of) being an input in hash
    SIG_DONOTUSE_PERSIST = 0x40		///< Do not use (fact of) being a global in hash
  };
private:
  uint4 sigmods;			///< Current settings to use for signature generation
  int4 maxiter;				///< Maximum number of iterations across data-flow graph
  int4 maxblockiter;			///< Maximum number of block iterations
  int4 maxvarnode;			///< Maximum number of Varnodes to signature
  map<int4,SignatureEntry *> sigmap; 	///< Map from Varnode to SignatureEntry overlay
  map<int4,BlockSignatureEntry *> blockmap; ///< Map from basic block to BlockSignatureEntry overlay
  void signatureIterate(void);		///< Do one iteration of hashing on the SignatureEntrys
  void signatureBlockIterate(void);	///< Do one iteration of hashing on the BlockSignatureEntrys
  void collectVarnodeSigs(void);	///< Generate the final feature for each Varnode from its SignatureEntry overlay
  void collectBlockSigs(void);		///< Generate the final feature(s) for each basic block from its BlockSignatureEntry overlay
  void varnodeClear(void);		///< Clear all SignatureEntry overlay objects
  void blockClear(void);		///< Clear all BlockSignatureEntry overlay objects
  void initializeBlocks(void);		///< Initialize BlockSignatureEntry overlays for the current function
  void flipVarnodes(void);		///< Store off \e current Varnode hash values as \e previous hash values
  void flipBlocks(void);		///< Store off \e current block hash values as \e previous hash values
public:
  virtual void clear(void);
  GraphSigManager(void);					///< Constructor
  virtual ~GraphSigManager(void) { varnodeClear(); }		///< Destructor
  void setMaxIteration(int4 val) { maxiter = val; }		///< Override the default iterations used for Varnode features
  void setMaxBlockIteration(int4 val) { maxblockiter = val; }	///< Override the default iterations used for block features
  void setMaxVarnode(int4 val) { maxvarnode = val; }		///< Set a maximum threshold for Varnodes in a function
  virtual void initializeFromStream(istream &s);
  virtual void setCurrentFunction(const Funcdata *f);
  virtual void generate(void);
  static bool testSettings(uint4 val);				///< Test for valid signature generation settings
};

/// \brief Given a Varnode, find its SignatureEntry overlay
///
/// \param vn is the given Varnode
/// \param sigMap is the map from Varnode to SignatureEntry
/// \return the corresponding SignatureEntry
inline SignatureEntry *SignatureEntry::mapToEntry(const Varnode *vn,const map<int4,SignatureEntry *> &sigMap)

{
  map<int4,SignatureEntry *>::const_iterator iter;

  iter = sigMap.find(vn->getCreateIndex());
  return (*iter).second;
}

/// \brief Given a Varnode, find its SignatureEntry overlay, collapsing shadows
///
/// If the corresponding SignatureEntry shadows another, the shadowed SignatureEntry is returned instead.
/// \param vn is the given Varnode
/// \param sigMap is the map from Varnode to SignatureEntry
/// \return the corresponding SignatureEntry
inline SignatureEntry *SignatureEntry::mapToEntryCollapse(const Varnode *vn,const map<int4,SignatureEntry *> &sigMap)

{
  SignatureEntry *res = mapToEntry(vn,sigMap);
  if (res->shadow == (SignatureEntry *)0)
    return res;
  return res->shadow;
}

/// \brief Calculate a hash describing the size of a given Varnode
///
/// The hash is computed from the size of the Varnode in bytes, as an integer value.
/// Depending on the signature settings, the hash incorporates the full value, or
/// it may truncate a value greater than 4.
/// \param vn is the given Varnode
/// \param modifiers are the settings being used for signature generation
/// \return the hash value
inline hashword SignatureEntry::hashSize(Varnode *vn,uint4 modifiers)

{
  hashword val = (hashword) vn->getSize();	// Size of varnode
  if ((modifiers&GraphSigManager::SIG_COLLAPSE_SIZE)!=0) {
    if (val>4)	// Treat sizes 4 and larger the same
      val = 4;
  }
  return val ^ (val<<7) ^ (val<<14) ^ (val<<21);
}

extern void simpleSignature(Funcdata *fd,Encoder &encoder);	///< Generate features for a single function
extern void debugSignature(Funcdata *fd,Encoder &encoder);	///< Generate features (with debug info) for a single function

} // End namespace ghidra
#endif
