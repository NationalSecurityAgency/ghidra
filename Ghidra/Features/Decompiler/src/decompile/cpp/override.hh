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

#ifndef __OVERRIDE__
#define __OVERRIDE__

#include "database.hh"

class FuncCallSpecs;		// Forward declaration

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
  /// \brief Enumeration of possible branch overrides
  enum {
    NONE = 0,			///< No override
    BRANCH = 1,			///< Replace primary CALL or RETURN with suitable BRANCH operation
    CALL = 2,			///< Replace primary BRANCH or RETURN with suitable CALL operation
    CALL_RETURN = 3,		///< Replace primary BRANCH or RETURN with suitable CALL/RETURN operation
    RETURN = 4			///< Replace primary BRANCH or CALL with a suitable RETURN operation
  };
private:
  map<Address,Address> forcegoto;	///< Force goto on jump at \b targetpc to \b destpc
  vector<int4> deadcodedelay;		///< Delay count indexed by address space
  map<Address,Address> indirectover;	///< Override indirect at \b call-point into direct to \b addr
  map<Address,FuncProto *> protoover;	///< Override prototype at \b call-point
  vector<Address> multistagejump;	///< Addresses of indirect jumps that need multistage recovery
  map<Address,uint4> flowoverride;	///< Override the CALL <-> BRANCH
  void clear(void);			///< Clear the entire set of overrides
  static string generateDeadcodeDelayMessage(int4 index,Architecture *glb);
public:
  ~Override(void) { clear(); }		///< Destructor
  void insertForceGoto(const Address &targetpc,const Address &destpc);
  void insertDeadcodeDelay(AddrSpace *spc,int4 delay);
  bool hasDeadcodeDelay(AddrSpace *spc) const;
  void insertIndirectOverride(const Address &callpoint,const Address &directcall);
  void insertProtoOverride(const Address &callpoint,FuncProto *p);
  void insertMultistageJump(const Address &addr);
  void insertFlowOverride(const Address &addr,uint4 type);

  void applyPrototype(Funcdata &data,FuncCallSpecs &fspecs) const;
  void applyIndirect(Funcdata &data,FuncCallSpecs &fspecs) const;
  bool queryMultistageJumptable(const Address &addr) const;
  void applyDeadCodeDelay(Funcdata &data) const;
  void applyForceGoto(Funcdata &data) const;
  bool hasFlowOverride(void) const { return (!flowoverride.empty()); }	///< Are there any flow overrides
  uint4 getFlowOverride(const Address &addr) const;
  void printRaw(ostream &s,Architecture *glb) const;
  void generateOverrideMessages(vector<string> &messagelist,Architecture *glb) const;
  void saveXml(ostream &s,Architecture *glb) const;
  void restoreXml(const Element *el,Architecture *glb);
  static string typeToString(uint4 tp);			///< Convert a flow override type to a string
  static uint4 stringToType(const string &nm);		///< Convert a string to a flow override type
};

#endif
