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
/// \file override.hh
/// \brief A system for sending override commands to the decompiler

#ifndef __OVERRIDE_HH__
#define __OVERRIDE_HH__

#include "database.hh"

namespace ghidra {

class FuncCallSpecs;		// Forward declaration

extern ElementId ELEM_DEADCODEDELAY;	///< Marshaling element \<deadcodedelay>
extern ElementId ELEM_FLOW;		///< Marshaling element \<flow>
extern ElementId ELEM_FORCEGOTO;	///< Marshaling element \<forcegoto>
extern ElementId ELEM_CALLDEST;		///< Marshaling element \<calldest>
extern ElementId ELEM_MULTISTAGEJUMP;	///< Marshaling element \<multistagejump>
extern ElementId ELEM_OVERRIDE;		///< Marshaling element \<override>
extern ElementId ELEM_PROTOOVERRIDE;	///< Marshaling element \<protooverride>

/// \brief An ephemeral unsigned range contract for one LOAD result in one invocation context
///
/// Addresses and scalar data survive a function restart without retaining graph pointers.
/// Provenance is audit information only. A consumer must separately establish that this contract
/// matches the current owner, SSA LOAD, use point, and (if present) required CBRANCH edge.
class ValueDomainConstraint {
  Address ownerEntry;
  Address loadAddress;
  int4 outputSize;
  Address switchAddress;
  uintb first;
  uintb last;
  Address descriptorAddress;
  string provenance;
  Address guardAddress;
  bool guardTrue;
  ValueDomainConstraint(const Address &owner,const Address &load,int4 size,const Address &use,
      uintb lo,uintb hi,const Address &descriptor,const string &source,
      const Address &guard,bool trueEdge,bool useRestricted);
public:
  ValueDomainConstraint(const Address &owner,const Address &load,int4 size,const Address &use,
      uintb lo,uintb hi,const Address &descriptor,const string &source,
      const Address &guard=Address(),bool trueEdge=false);
  ValueDomainConstraint(const Address &owner,const Address &load,int4 size,uintb lo,uintb hi,
      const Address &descriptor,const string &source,
      const Address &guard=Address(),bool trueEdge=false);
  const Address &getOwnerEntry(void) const { return ownerEntry; }
  const Address &getLoadAddress(void) const { return loadAddress; }
  int4 getOutputSize(void) const { return outputSize; }
  const Address &getSwitchAddress(void) const { return switchAddress; }
  bool isUseRestricted(void) const { return !switchAddress.isInvalid(); }
  uintb getFirst(void) const { return first; }
  uintb getLast(void) const { return last; }
  const Address &getDescriptorAddress(void) const { return descriptorAddress; }
  const string &getProvenance(void) const { return provenance; }
  const Address &getGuardAddress(void) const { return guardAddress; }
  bool isGuardTrue(void) const { return guardTrue; }
  bool hasSameSelector(const ValueDomainConstraint &other) const;
  void encode(Encoder &encoder) const;
  static ValueDomainConstraint decodeFromElement(Decoder &decoder);
};

/// \brief A container of commands that override the decompiler's default behavior for a single function
///
/// Information about a particular function that can be overridden includes:
///   - sub-functions:  How they are called and where they call to
///   - jumptables:     Mark indirect jumps that need multistage analysis
///   - deadcode:       Details about how dead code is eliminated
///   - data-flow:      Override the interpretation of specific branch instructions
///
/// Commands exist independently of the main data-flow, control-flow, and symbol structures
/// and survive decompilation restart. A few analyses, mid transformation, insert a new command
/// to fix a problem that was discovered too late and then force a restart via Funcdata::setRestartPending()
///
/// The class accept new commands via the insert* methods. The decompiler applies them by
/// calling the apply* or get* methods.
class Override {
public:
  /// \brief Abstract class performing an override of p-code on an instruction
  ///
  /// Instances operate directly on raw p-code emitted for a single instruction,
  /// prior to incorporation in the syntax tree.
  class Record {
  public:
    virtual ~Record(void) {}		///< Destructor

    /// \brief Perform p-code modifications for the instruction at the given address
    ///
    /// \param addr is the given address of the instruction
    /// \param data is the function
    virtual void performOverride(const Address &addr,Funcdata &data) const=0;

    /// \brief Encode \b this record to stream
    ///
    /// \param encoder is the stream
    /// \param addr is the address of the instruction the override applies to
    virtual void encode(Encoder &encoder,const Address &addr) const=0;

    /// \brief Print a description of the override as a console message
    ///
    /// \param s is the stream to write to
    /// \param addr is the address \b this override applies to
    virtual void printRaw(ostream &s,const Address &addr) const=0;

    static Record *allocateFlow(const string &name);		///< Return a corresponding flow override record
    static Record *allocateCallDest(const string &name,const Address &dest);	///< Return a corresponding call destination override
  };

  /// \brief Override a CALL, CALLIND, or RETURN to become a BRANCH or BRANCHIND
  class Branch : public Record {
  public:
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;		///< Name of the branch override record
  };

  /// \brief Override a BRANCH, BRANCHIND, or RETURN to become a CALL or CALLIND operation
  class Call : public Record {
  public:
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;		///< Name of the call override record
  };

  /// \brief Override a BRANCH, BRANCHIND, or RETURN to become a CALL or CALLIND, followed by a RETURN
  class CallReturn : public Record {
  public:
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;		///< Name of the callreturn override record
  };

  /// \brief Override a BRANCHIND or CALLIND to become a RETURN
  class Return : public Record {
  public:
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;		///< Name of the return override record
  };

  /// \brief Convert a CALLOTHER to a direct CALL
  class CallotherCall : public Record {
    Address callAddress;	///< Address of direct CALL
  public:
    CallotherCall(const Address &dest) : callAddress(dest) {}	///< Constructor
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;	///< Name of the callother -> call override record
  };

  /// \brief Convert a CALLOTHER to a BRANCH
  class CallotherBranch : public Record {
    Address branchAddress;	///< Destination of BRANCH
  public:
    CallotherBranch(const Address &dest) : branchAddress(dest) {}	///< Constructor
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;	///< Name of the callther -> branch override record
  };

  /// \brief Convert CALL or CALLIND into a CALL with a new destination address
  class CallCall : public Record {
    Address callAddress;	///< Address of (new) CALL
  public:
    CallCall(const Address &dest) : callAddress(dest) {}	///< Constructor
    virtual void performOverride(const Address &addr,Funcdata &data) const;
    virtual void encode(Encoder &encoder,const Address &addr) const;
    virtual void printRaw(ostream &s,const Address &addr) const;
    static const string NAME;	///< Name of the call -> call override record
  };
private:
  map<Address,Record *> pcodeover;	///< Raw p-code overrides for instructions
  map<Address,Address> forcegoto;	///< Force goto on jump at \b targetpc to \b destpc
  vector<int4> deadcodedelay;		///< Delay count indexed by address space
  map<Address,Address> deindirect;	///< Convert CALLIND into CALL with recovered direct \b addr
  map<Address,FuncProto *> protoover;	///< Override prototype at \b call-point
  vector<Address> multistagejump;	///< Addresses of indirect jumps that need multistage recovery
  vector<ValueDomainConstraint> valueDomains;	///< Context-specific LOAD result/use contracts
  void clear(void);			///< Clear the entire set of overrides
  static string generateDeadcodeDelayMessage(int4 index,Architecture *glb);
public:
  ~Override(void) { clear(); }		///< Destructor
  void insertValueDomainConstraint(const ValueDomainConstraint &constraint);
  const vector<ValueDomainConstraint> &getValueDomainConstraints(void) const { return valueDomains; }
  void copyValueDomainConstraints(const Override &other) { valueDomains = other.valueDomains; }
  void insertForceGoto(const Address &targetpc,const Address &destpc);
  void insertDeadcodeDelay(AddrSpace *spc,int4 delay);
  bool hasDeadcodeDelay(AddrSpace *spc) const;
  void insertDeindirect(const Address &callPoint,const Address &directAddr);
  void insertProtoOverride(const Address &callpoint,FuncProto *p);
  void insertMultistageJump(const Address &addr);
  void insertFlowOverride(const Address &addr,const string &type);
  void insertDestinationOverride(const Address &addr,const Address &dest,const string &type);

  void applyPrototype(Funcdata &data,FuncCallSpecs &fspecs) const;
  void applyIndirect(Funcdata &data,FuncCallSpecs &fspecs) const;
  bool queryMultistageJumptable(const Address &addr) const;
  void applyDeadCodeDelay(Funcdata &data) const;
  void applyForceGoto(Funcdata &data) const;
  bool hasPCodeOverride(void) const { return (!pcodeover.empty()); }	///< Are there any flow overrides
  const Record *getPCodeOverride(const Address &addr) const;
  void printRaw(ostream &s,Architecture *glb) const;
  void generateOverrideMessages(vector<string> &messagelist,Architecture *glb) const;
  void encode(Encoder &encoder,Architecture *glb) const;
  void decode(Decoder &decoder,Architecture *glb);
};

} // End namespace ghidra
#endif
