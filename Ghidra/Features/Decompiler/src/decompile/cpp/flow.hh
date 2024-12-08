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
/// \file flow.hh
/// \brief Utilities for following control-flow in p-code generated from machine instructions

#ifndef __FLOW_HH__
#define __FLOW_HH__

#include "funcdata.hh"

namespace ghidra {

/// \brief A class for generating the control-flow structure for a single function
///
/// Control-flow for the function is generated in two phases:  the method generateOps() produces
/// all the raw p-code ops for the function, and the method generateBlocks() organizes the
/// p-code ops into basic blocks (PcodeBlockBasic).
/// In generateOps(), p-code is generated for every machine instruction that is reachable starting
/// with the entry point address of the function. All possible flow is followed, trimming flow
/// at instructions that end with the formal RETURN p-code operation.  CALL and CALLIND are treated
/// as fall-through operations, and flow is not followed into the sub-function.
///
/// The class supports various options for handling corner cases during the flow following process,
/// including how to handle:
///   - Flow out of range (specified by setRange())
///   - Flow into unimplemened instructions
///   - Flow into unaccessible data
///   - Flow into previously traversed data at an \e off cut (\b reinterpreted data)
///   - Flow that (seemingly) doesn't end, exceeding a threshold on the number of instructions
///
/// In generateBlocks(), all previously generated PcodeOp instructions are assigned to a
/// PcodeBlockBasic.  These objects define the formal basic block structure of the function.
/// Directed control-flow edges between the blocks are created at this time based on the
/// flow of p-code.
///
/// A Funcdata object provided to the constructor holds:
///   - The generated PcodeOp objects (within its PcodeOpBank).
///   - The control-flow graph (within its BlockGraph)
///   - The list of discovered sub-function calls (as FuncCallSpec objects)
///
/// The Translate object (provided by the Architecture owning the function) generates
/// the raw p-code ops for a single instruction.  This FlowInfo class also handles
/// p-code \e injection triggers encountered during flow following, primarily using
/// the architecture's PcodeInjectLibrary to resolve them.
class FlowInfo {
public:
  enum { ignore_outofbounds = 1,	///< Ignore/truncate flow into addresses out of the specified range
	 ignore_unimplemented = 2,	///< Treat unimplemented instructions as a NOP (no operation)
	 error_outofbounds = 4,		///< Throw an exception for flow into addresses out of the specified range
	 error_unimplemented = 8,	///< Throw an exception for flow into unimplemented instructions
	 error_reinterpreted = 0x10,	///< Throw an exception for flow into previously encountered data at a difference \e cut
	 error_toomanyinstructions = 0x20,	///< Throw an exception if too many instructions are encountered
	 unimplemented_present = 0x40,	///< Indicate we have encountered unimplemented instructions
	 baddata_present = 0x80,	///< Indicate we have encountered flow into unaccessible data
	 outofbounds_present = 0x100,	///< Indicate we have encountered flow out of the specified range
	 reinterpreted_present = 0x200,	///< Indicate we have encountered reinterpreted data
	 toomanyinstructions_present = 0x400, 	///< Indicate the maximum instruction threshold was reached
	 possible_unreachable = 0x1000,	///< Indicate a CALL was converted to a BRANCH and some code may be unreachable
	 flow_forinline = 0x2000,	///< Indicate flow is being generated to in-line (a function)
	 record_jumploads = 0x4000	///< Indicate that any jump table recovery should record the table structure
 };
private:
  /// \brief A helper function describing the number of bytes in a machine instruction and the starting p-code op
  struct VisitStat {
    SeqNum seqnum;	///< Sequence number of first PcodeOp in the instruction (or INVALID if no p-code)
    int4 size;		///< Number of bytes in the instruction
  };
  Architecture *glb;			///< Owner of the function
  Funcdata &data;			///< The function being flow-followed
  PcodeOpBank &obank;			///< Container for generated p-code
  BlockGraph &bblocks;			///< Container for the control-flow graph
  vector<FuncCallSpecs *> &qlst;	///< The list of discovered sub-function call sites
  PcodeEmitFd emitter;			///< PCodeOp factory (configured to allocate into \b data and \b obank)
  vector<Address> unprocessed;		///< Addresses which are permanently unprocessed
  vector<Address> addrlist;		///< Addresses to which there is flow
  vector<PcodeOp *> tablelist;		///< List of BRANCHIND ops (preparing for jump table recovery)
  vector<PcodeOp *> injectlist;		///< List of p-code ops that need injection
  map<Address,VisitStat> visited;	///< Map of machine instructions that have been visited so far
  list<PcodeOp *> block_edge1;		///< Source p-code op (Edges between basic blocks)
  list<PcodeOp *> block_edge2;		///< Destination p-code op (Edges between basic blocks)
  uint4 insn_count;			///< Number of instructions flowed through
  uint4 insn_max;			///< Maximum number of instructions
  Address baddr;			///< Start of range in which we are allowed to flow
  Address eaddr;			///< End of range in which we are allowed to flow
  Address minaddr;			///< Start of actual function range
  Address maxaddr;			///< End of actual function range
  bool flowoverride_present;		///< Does the function have registered flow override instructions
  uint4 flags;				///< Boolean options for flow following
  Funcdata *inline_head;		///< First function in the in-lining chain
  set<Address> *inline_recursion;	///< Active list of addresses for function that are in-lined
  set<Address> inline_base;		///< Storage for addresses of functions that are in-lined
  bool hasPossibleUnreachable(void) const { return ((flags & possible_unreachable)!=0); }	///< Are there possible unreachable ops
  void setPossibleUnreachable(void) { flags |= possible_unreachable; }	///< Mark that there may be unreachable ops
  void clearProperties(void);		///< Clear any discovered flow properties
  bool seenInstruction(const Address &addr) const {
    return (visited.find(addr) != visited.end()); }	///< Has the given instruction (address) been seen in flow
  PcodeOp *fallthruOp(PcodeOp *op) const;		///< Find fallthru pcode-op for given op
  void newAddress(PcodeOp *from,const Address &to);	///< Register a new (non fall-thru) flow target
  void deleteRemainingOps(list<PcodeOp *>::const_iterator oiter);
  PcodeOp *xrefControlFlow(list<PcodeOp *>::const_iterator oiter,bool &startbasic,bool &isfallthru,FuncCallSpecs *fc);
  bool processInstruction(const Address &curaddr,bool &startbasic);
  void fallthru(void);					///< Process (the next) sequence of instructions in fall-thru order
  PcodeOp *findRelTarget(PcodeOp *op,Address &res) const;
  void findUnprocessed(void);				///< Add any remaining un-followed addresses to the \b unprocessed list
  void dedupUnprocessed(void);				///< Get rid of duplicates in the \b unprocessed list
  void fillinBranchStubs(void);				///< Fill-in artificial HALT p-code for \b unprocessed addresses
  void collectEdges(void);				///< Collect edges between basic blocks as PcodeOp to PcodeOp pairs
  void splitBasic(void);				///< Split raw p-code ops up into basic blocks
  void connectBasic(void);				///< Generate edges between basic blocks
  bool setFallthruBound(Address &bound);		///< Find end of the next unprocessed region
  void handleOutOfBounds(const Address &fromaddr,const Address &toaddr);
  PcodeOp *artificialHalt(const Address &addr,uint4 flag);	///< Create an artificial halt p-code op
  void reinterpreted(const Address &addr);		///< Generate warning message or exception for a \e reinterpreted address
  bool checkForFlowModification(FuncCallSpecs &fspecs);
  void queryCall(FuncCallSpecs &fspecs);		///< Try to recover the Funcdata object corresponding to a given call
  bool setupCallSpecs(PcodeOp *op,FuncCallSpecs *fc);	///< Set up the FuncCallSpecs object for a new call site
  bool setupCallindSpecs(PcodeOp *op,FuncCallSpecs *fc);
  void xrefInlinedBranch(PcodeOp *op);			///< Check for control-flow in a new injected p-code op
  void doInjection(InjectPayload *payload,InjectContext &icontext,PcodeOp *op,FuncCallSpecs *fc);
  void injectUserOp(PcodeOp *op);			///< Perform \e injection for a given user-defined p-code op
  bool inlineSubFunction(FuncCallSpecs *fc);		///< In-line the sub-function at the given call site
  bool injectSubFunction(FuncCallSpecs *fc);		///< Perform \e injection replacing the CALL at the given call site
  void checkContainedCall(void);
  void checkMultistageJumptables(void);
  void recoverJumpTables(vector<JumpTable *> &newTables,vector<PcodeOp *> &notreached);
  void deleteCallSpec(FuncCallSpecs *fc);		///< Remove the given call site from the list for \b this function
  void truncateIndirectJump(PcodeOp *op,JumpTable::RecoveryMode mode);  ///< Treat indirect jump as CALLIND/RETURN
  static bool isInArray(vector<PcodeOp *> &array,PcodeOp *op);
public:
  FlowInfo(Funcdata &d,PcodeOpBank &o,BlockGraph &b,vector<FuncCallSpecs *> &q);	///< Constructor
  FlowInfo(Funcdata &d,PcodeOpBank &o,BlockGraph &b,vector<FuncCallSpecs *> &q,const FlowInfo *op2);	///< Cloning constructor
  void setRange(const Address &b,const Address &e) { baddr = b; eaddr = e; }	///< Establish the flow bounds
  void setMaximumInstructions(uint4 max) { insn_max = max; }	///< Set the maximum number of instructions
  void setFlags(uint4 val) { flags |= val; }	///< Enable a specific option
  void clearFlags(uint4 val) { flags &= ~val; }	///< Disable a specific option
  PcodeOp *target(const Address &addr) const;	///< Return first p-code op for instruction at given address
  PcodeOp *branchTarget(PcodeOp *op) const;	///< Find the target referred to by a given BRANCH or CBRANCH
  void generateOps(void);			///< Generate raw control-flow from the function's base address
  void generateBlocks(void);			///< Generate basic blocks from the raw control-flow
  bool testHardInlineRestrictions(Funcdata *inlinefd,PcodeOp *op,Address &retaddr);
  bool checkEZModel(void) const;		///< Check if \b this flow matches the EX in-lining model
  void injectPcode(void);			///< Perform substitution on any op that requires \e injection
  void forwardRecursion(const FlowInfo &op2);	///< Pull in-lining recursion information from another flow
  void inlineClone(const FlowInfo &inlineflow,const Address &retaddr);
  void inlineEZClone(const FlowInfo &inlineflow,const Address &calladdr);
  int4 getSize(void) const { return (int4)(maxaddr.getOffset() - minaddr.getOffset()); }	///< Get the number of bytes covered by the flow
  bool hasInject(void) const { return !injectlist.empty(); }		///< Does \b this flow have injections
  bool hasUnimplemented(void) const { return ((flags & unimplemented_present)!=0); }	///< Does \b this flow have unimiplemented instructions
  bool hasBadData(void) const { return ((flags & baddata_present)!=0); }		///< Does \b this flow reach inaccessible data
  bool hasOutOfBounds(void) const { return ((flags & outofbounds_present)!=0); }	///< Does \b this flow out of bound
  bool hasReinterpreted(void) const { return ((flags & reinterpreted_present)!=0); }	///< Does \b this flow reinterpret bytes
  bool hasTooManyInstructions(void) const { return ((flags & toomanyinstructions_present)!=0); }	///< Does \b this flow have too many instructions
  bool isFlowForInline(void) const { return ((flags & flow_forinline)!=0); }	///< Is \b this flow to be in-lined
  bool doesJumpRecord(void) const { return ((flags & record_jumploads)!=0); }	///< Should jump table structure be recorded
};

} // End namespace ghidra
#endif
