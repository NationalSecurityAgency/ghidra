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
/// \file userop.hh
/// \brief Classes for more detailed definitions of user defined p-code operations

#ifndef __USEROP_HH__
#define __USEROP_HH__

#include "typeop.hh"

namespace ghidra {

extern AttributeId ATTRIB_FARPOINTER;	///< Marshaling attribute "farpointer"
extern AttributeId ATTRIB_INPUTOP;	///< Marshaling attribute "inputop"
extern AttributeId ATTRIB_OUTPUTOP;	///< Marshaling attribute "outputop"
extern AttributeId ATTRIB_USEROP;	///< Marshaling attribute "userop"

extern ElementId ELEM_CONSTRESOLVE;	///< Marshaling element \<constresolve>
extern ElementId ELEM_JUMPASSIST;	///< Marshaling element \<jumpassist>
extern ElementId ELEM_SEGMENTOP;	///< Marshaling element \<segmentop>

/// \brief The base class for a detailed definition of a user-defined p-code operation
///
/// Within the raw p-code framework, the CALLOTHER opcode represents a user defined
/// operation. At this level, the operation is just a placeholder for inputs and outputs
/// to same black-box procedure. The first input parameter (index 0) must be a constant
/// id associated with the particular procedure. Classes derived off of this base class
/// provide a more specialized definition of an operation/procedure. The specialized classes
/// are managed via UserOpManage and are associated with CALLOTHER ops via the constant id.
///
/// The derived classes can in principle implement any functionality, tailored to the architecture
/// or program. At this base level, the only commonality is a formal \b name of the operator and
/// its CALLOTHER index.  A facility for reading in implementation details is provided via decode().
class UserPcodeOp {
public:
  /// \brief Enumeration of different boolean properties that can be assigned to a CALLOTHER
  enum userop_flags {
    annotation_assignment = 1,	///< Displayed as assignment, `in1 = in2`, where the first parameter is an annotation
    no_operator = 2,		///< Don't emit special token, just emit the first input parameter as expression
    display_string = 4		///< Emit as a string constant
  };
  /// \brief User-op class encoded as an enum
  enum userop_type {
    unspecialized = 1,			///< Encoding for UnspecializedPcodeOp
    injected = 2,			///< InjectedUserOp
    volatile_read = 3,			///< VolatileReadOp
    volatile_write = 4,			///< VolatileWriteOp
    segment = 5,			///< SegmentOp
    jumpassist = 6,			///< JumpAssistOp
    string_data = 7,			///< InternalStringOp
    datatype = 8			///< DatatypeUserOp
  };
  static const uint4 BUILTIN_STRINGDATA;	///< Built-in id for the InternalStringOp
  static const uint4 BUILTIN_VOLATILE_READ;	///< Built-in id for VolatileReadOp
  static const uint4 BUILTIN_VOLATILE_WRITE;	///< Built-in id for VolatileWriteOp
  static const uint4 BUILTIN_MEMCPY;		///< Built-in id for memcpy
  static const uint4 BUILTIN_STRNCPY;		///< Built-in id for strcpy
  static const uint4 BUILTIN_WCSNCPY;		///< Built-in id for wcsncpy
protected:
  string name;			///< Low-level name of p-code operator
  Architecture *glb;		///< Architecture owning the user defined op
  uint4 type;			///< Encoded class type (userop_type)
  int4 useropindex;		///< Index passed in the CALLOTHER op
  uint4 flags;			///< Boolean attributes of the CALLOTHER
public:
  UserPcodeOp(const string &nm,Architecture *g,uint4 tp,int4 ind) {
    name = nm; glb = g; type = tp; useropindex = ind; flags = 0; }	///< Construct from name and index
  const string &getName(void) const { return name; }		///< Get the low-level name of the p-code op
  uint4 getType(void) const { return type; }			///< Get the encoded class type
  int4 getIndex(void) const { return useropindex; }		///< Get the constant id of the op
  uint4 getDisplay(void) const {
    return (flags & (annotation_assignment | no_operator | display_string)); }	///< Get display type (0=functional)
  virtual ~UserPcodeOp(void) {}					///< Destructor

  /// \brief Get the symbol representing this operation in decompiled code
  ///
  /// This will return the symbol formally displayed in source code, which can be
  /// tailored more than the low-level name
  /// \param op is the operation (in context) where a symbol is needed
  /// \return the symbol as a string
  virtual string getOperatorName(const PcodeOp *op) const {
    return name; }

  /// \brief Return the output data-type of the user-op if specified
  ///
  /// \param op is the instantiation of the user-op
  /// \return the data-type or null to indicate the data-type is unspecified
  virtual Datatype *getOutputLocal(const PcodeOp *op) const { return (Datatype *)0; }

  /// \brief Return the input data-type to the user-op in the given slot
  ///
  /// \param op if the instantiation of the user-op
  /// \param slot is the given input slot
  /// \return the data-type or null to indicate the data-type is unspecified
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const { return (Datatype *)0; }

  /// \brief Assign a size to an annotation input to \b this userop
  ///
  /// Assuming an annotation refers to a special symbol accessed by \b this operation, retrieve the
  /// size (in bytes) of the symbol, which isn't ordinarily stored as part of the annotation.
  /// \param vn is the annotation Varnode
  /// \param op is the specific PcodeOp instance of \b this userop
  virtual int4 extractAnnotationSize(const Varnode *vn,const PcodeOp *op);

  /// \brief Restore the detailed description from a stream element
  ///
  /// The details of how a user defined operation behaves are parsed from the element.
  /// \param decoder is the stream decoder
  virtual void decode(Decoder &decoder)=0;
};

/// \brief A user defined p-code op with no specialization
///
/// This class is used by the manager for CALLOTHER indices that have not been
/// mapped to a specialization. The p-code operation has the (SLEIGH assigned) name,
/// but still has an unknown effect.
class UnspecializedPcodeOp : public UserPcodeOp {
public:
  UnspecializedPcodeOp(const string &nm,Architecture *g,int4 ind)
    : UserPcodeOp(nm,g,unspecialized,ind) {}		///< Constructor
  virtual void decode(Decoder &decoder) {}
};

/// \brief Generic user defined operation that provides input/output data-types
///
/// The CALLOTHER acts a source of data-type information within data-flow.
class DatatypeUserOp : public UserPcodeOp {
  Datatype *outType;		///< Data-type of the output
  vector<Datatype *> inTypes;	///< Data-type of the input(s)
public:
  DatatypeUserOp(const string &nm,Architecture *g,int4 ind,Datatype *out,
		 Datatype *in0=(Datatype *)0,Datatype *in1=(Datatype *)0,
		 Datatype *in2=(Datatype *)0,Datatype *in3=(Datatype *)0);
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual void decode(Decoder &decoder) {}
};

/// \brief A user defined operation that is injected with other p-code
///
/// The system can configure user defined p-code ops as a hook point within the
/// control-flow where other p-code is injected during analysis. This class maps
/// the raw CALLOTHER p-code op, via its constant id, to its injection object.
/// The injection object is also referenced by an id and is managed by PcodeInjectLibrary.
class InjectedUserOp : public UserPcodeOp {
  uint4 injectid;			///< The id of the injection object (to which this op maps)
public:
  InjectedUserOp(const string &nm,Architecture *g,int4 ind,int4 injid)
    : UserPcodeOp(nm,g,injected,ind) { injectid = injid; }	///< Constructor
  uint4 getInjectId(void) const { return injectid; }	///< Get the id of the injection object
  virtual void decode(Decoder &decoder);
};

/// \brief A base class for operations that access volatile memory
///
/// The decompiler models volatile memory by converting any direct read or write of
/// the memory to a function that \e accesses the memory. This class and its derived
/// classes model such functions. Within the p-code control-flow, dedicated user defined
/// ops serve as a placeholder for the (possibly unknown) effects of modifying/accessing the
/// memory and prevent accidental constant propagation.
class VolatileOp : public UserPcodeOp {
protected:
  static string appendSize(const string &base,int4 size);	///< Append a suffix to a string encoding a specific size
public:
  VolatileOp(const string &nm,Architecture *g,uint4 tp,int4 ind)
    : UserPcodeOp(nm,g,tp,ind) { }				///< Constructor
  virtual void decode(Decoder &decoder) {}			///< Currently volatile ops only need their name
};

/// \brief An operation that reads from volatile memory
///
/// This CALLOTHER p-code operation takes as its input parameter, after the constant id,
/// a reference Varnode to the memory being read. The output returned by this operation
/// is the actual value read from memory.
class VolatileReadOp : public VolatileOp {
public:
  VolatileReadOp(const string &nm,Architecture *g,bool functional)
    : VolatileOp(nm,g,volatile_read,BUILTIN_VOLATILE_READ) { flags = functional ? 0 : no_operator; }	///< Constructor
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual int4 extractAnnotationSize(const Varnode *vn,const PcodeOp *op);
};

/// \brief An operation that writes to volatile memory
///
/// This CALLOTHER p-code operation takes as its input parameters:
///   - Constant id
///   - Reference Varnode to the memory being written
///   - The Varnode value being written to the memory
class VolatileWriteOp : public VolatileOp {
public:
  VolatileWriteOp(const string &nm,Architecture *g,bool functional)
    : VolatileOp(nm,g,volatile_write,BUILTIN_VOLATILE_WRITE) { flags = functional ? 0 : annotation_assignment; }	///< Constructor
  virtual string getOperatorName(const PcodeOp *op) const;
  virtual Datatype *getInputLocal(const PcodeOp *op,int4 slot) const;
  virtual int4 extractAnnotationSize(const Varnode *vn,const PcodeOp *op);
};

/// \brief A user defined p-code op that has a dynamically defined procedure
///
/// The behavior of this op on constant inputs can be dynamically defined.
/// This class defines a unify() method that picks out the input varnodes to the
/// operation, given the root PcodeOp.  The input varnodes would generally just be
/// the input varnodes to the raw CALLOTHER after the constant id, but skipping, reordering,
/// or other tree traversal is possible.
///
/// This class also defines an execute() method that computes the output given
/// constant inputs (matching the format determined by unify()).
class TermPatternOp : public UserPcodeOp {
public:
  TermPatternOp(const string &nm,Architecture *g,uint4 tp,int4 ind) : UserPcodeOp(nm,g,tp,ind) {}	///< Constructor
  virtual int4 getNumVariableTerms(void) const=0;		///< Get the number of input Varnodes expected

  /// \brief Gather the formal input Varnode objects given the root PcodeOp
  ///
  /// \param data is the function being analyzed
  /// \param op is the root operation
  /// \param bindlist will hold the ordered list of input Varnodes
  /// \return \b true if the requisite inputs were found
  virtual bool unify(Funcdata &data,PcodeOp *op,vector<Varnode *> &bindlist) const=0;

  /// \brief Compute the output value of \b this operation, given constant inputs
  ///
  /// \param input is the ordered list of constant inputs
  /// \return the resulting value as a constant
  virtual uintb execute(const vector<uintb> &input) const=0;
};

/// \brief The \e segmented \e address operator
///
/// This op is a placeholder for address mappings involving \b segments.
///The map goes between a \b high-level view of a pointer, consisting of multiple pieces,
/// and a \b low-level view, where there is only a single absolute pointer.
/// The mapping could be
///    - a virtual to physical mapping for instance  or
///    - a segment + near pointer to a full address
///
/// The output of the operator is always a full low-level pointer.
/// The operator takes two inputs:
///    - the \b base or \b segment and
///    - the high-level \b near pointer
///
/// High-level analysis can ignore the base/segment and any
/// normalization on the near pointer.
/// Emitted expressions involving \b this segment op prints only the \b near portion.
/// Data-type information propagates only through this high-level side.
///
/// The decompiler looks for the term-tree defined in SegmentOp
/// and replaces it with the SEGMENTOP operator in any p-code it analyzes.
/// The core routine that looks for the term-tree is unify().
class SegmentOp : public TermPatternOp {
  AddrSpace *spc;		///< The physical address space into which a segmented pointer points
  int4 injectId;		///< Id of InjectPayload that emulates \b this operation
  int4 baseinsize;		///< The size in bytes of the \e base or \e segment value
  int4 innerinsize;		///< The size in bytes of the \e near pointer value
  bool supportsfarpointer;	///< Is \b true if the joined pair base:near acts as a \b far pointer
  VarnodeData constresolve;	///< How to resolve constant near pointers
public:
  SegmentOp(const string &nm,Architecture *g,int4 ind);		///< Constructor
  AddrSpace *getSpace(void) const { return spc; }		///< Get the address space being pointed to
  bool hasFarPointerSupport(void) const { return supportsfarpointer; }	///< Return \b true, if \b this op supports far pointers
  int4 getBaseSize(void) const { return baseinsize; }		///< Get size in bytes of the base/segment value
  int4 getInnerSize(void) const { return innerinsize; }		///< Get size in bytes of the near value
  const VarnodeData &getResolve(void) const { return constresolve; }	///< Get the default register for resolving indirect segments
  virtual int4 getNumVariableTerms(void) const { if (baseinsize!=0) return 2; return 1; }
  virtual bool unify(Funcdata &data,PcodeOp *op,vector<Varnode *> &bindlist) const;
  virtual uintb execute(const vector<uintb> &input) const;
  virtual void decode(Decoder &decoder);
};

/// \brief A user defined p-code op for assisting the recovery of jump tables.
///
/// An instance of this class refers to p-code script(s)
/// that describe how to parse the jump table from the load image. Possible scripts include:
///  - (if present) \b index2case describes how to get case values from an index 0..size-1
///  - \b index2addr describes how to get address values from the same index range
///  - \b defaultaddr describes how to calculate the switch's default address
///  - (if present) \b calcsize recovers the number of indices in the table
///
/// This class stores injection ids. The scripts themselves are managed by PcodeInjectLibrary.
class JumpAssistOp : public UserPcodeOp {
  int4 index2case;		///< Id of p-code script performing index2case (== -1 if no script and index==case)
  int4 index2addr;		///< Id of p-code script performing index2addr (must be present)
  int4 defaultaddr;		///< Id of p-code script performing calculation of default address (must be present)
  int4 calcsize;		///< Id of p-code script that calculates number of indices (== -1 if no script)
public:
  JumpAssistOp(Architecture *g);	///< Constructor
  int4 getIndex2Case(void) const { return index2case; }		///< Get the injection id for \b index2case
  int4 getIndex2Addr(void) const { return index2addr; }		///< Get the injection id for \b index2addr
  int4 getDefaultAddr(void) const { return defaultaddr; }	///< Get the injection id for \b defaultaddr
  int4 getCalcSize(void) const { return calcsize; }		///< Get the injection id for \b calcsize
  virtual void decode(Decoder &decoder);
};

/// \brief An op that displays as an internal string
///
/// The user op takes no input parameters.  In the decompiler output, it displays as a quoted string.  The
/// string is associated with the address assigned to the user op and is pulled from StringManager as \e internal.
class InternalStringOp : public UserPcodeOp {
public:
  InternalStringOp(Architecture *g);	///< Constructor
  virtual Datatype *getOutputLocal(const PcodeOp *op) const;
  virtual void decode(Decoder &decoder) {}
};

/// \brief Manager/container for description objects (UserPcodeOp) of user defined p-code ops
///
/// The description objects are referenced by the CALLOTHER constant id, (or by name during initialization).
/// During initialize(), every user defined p-code op presented by the Architecture is
/// assigned a default UnspecializedPcodeOp description.  Further processing of the .cspec or .pspec
/// may reassign a more specialized description object by parsing specific tags using
/// on of \b this class's parse* methods.
class UserOpManage {
  Architecture *glb;			///< Architecture this manager is associated with
  vector<UserPcodeOp *> useroplist;	///< Description objects indexed by CALLOTHER constant id
  map<uint4,UserPcodeOp *> builtinmap;	///< Map from builtin ids to description objects
  map<string,UserPcodeOp *> useropmap;	///< A map from the name of the user defined operation to a description object
  vector<SegmentOp *> segmentop;	///< Segment operations supported by this Architecture
  void registerOp(UserPcodeOp *op);	///< Insert a new UserPcodeOp description object in the map(s)
public:
  UserOpManage(void);			///< Construct an empty manager
  ~UserOpManage(void);			///< Destructor
  void initialize(Architecture *g);	///< Initialize description objects for all user defined ops
  int4 numSegmentOps(void) const { return segmentop.size(); }	///< Number of segment operations supported

  UserPcodeOp *getOp(uint4 i) const;		///< Retrieve a user-op description object by index
  UserPcodeOp *getOp(const string &nm) const;	///< Retrieve description by name

  UserPcodeOp *registerBuiltin(uint4 i);	///< Make sure an active record exists for the given built-in op

  /// Retrieve a segment-op description object by index
  /// \param i is the index
  /// \return the indicated segment-op description
  SegmentOp *getSegmentOp(int4 i) const {
    if (i>=segmentop.size()) return (SegmentOp *)0;
    return segmentop[i];
  }

  void decodeSegmentOp(Decoder &decoder,Architecture *glb);			///< Parse a \<segmentop> element
  void decodeVolatile(Decoder &decoder,Architecture *glb);			///< Parse a \<volatile> element
  void decodeCallOtherFixup(Decoder &decoder,Architecture *glb);		///< Parse a \<callotherfixup> element
  void decodeJumpAssist(Decoder &decoder,Architecture *glb);			///< Parse a \<jumpassist> element
  void manualCallOtherFixup(const string &useropname,const string &outname,
			    const vector<string> &inname,const string &snippet,Architecture *glb);
};

} // End namespace ghidra
#endif
