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
#ifndef __CONTEXT_GHIDRA__
#define __CONTEXT_GHIDRA__

/// \file ghidra_context.hh
/// \brief Obtaining context information from a Ghidra client

#include "globalcontext.hh"
#include "ghidra_arch.hh"

/// \brief An implementation of a ContextDatabase obtaining context information via a Ghidra client
///
/// This only implements the tracked register parts of the interface. In fact, this only implements
/// the single method getTrackedSet(). Other methods that get or set the low-level (disassembly)
/// context variables will throw an exception. The low-level context is only needed by the
/// Sleigh disassembly engine, which is being provided by the Ghidra client in this use case.
class ContextGhidra : public ContextDatabase {
  ArchitectureGhidra *glb;			///< Architecture and connection to the Ghidra client
  mutable TrackedSet cache;			///< A cache of previously fetched tracked registers.
  virtual ContextBitRange &getVariable(const string &nm) {
    throw LowlevelError("getVariable should not be called for GHIDRA"); }
  virtual const ContextBitRange &getVariable(const string &nm) const {
    throw LowlevelError("getVariable should not be called for GHIDRA"); }
  virtual void getRegionForSet(vector<uintm *> &res,const Address &addr1,const Address &addr2,int4 num,uintm mask) {
    throw LowlevelError("getRegionForSet should not be called for GHIDRA"); }
  virtual void getRegionToChangePoint(vector<uintm *> &res,const Address &addr,int4 num,uintm mask) {
    throw LowlevelError("getRegionToChangePoint should not be called for GHIDRA"); }
  virtual const uintm *getDefaultValue(void) const {
    throw LowlevelError("getDefaultValue should not be called for GHIDRA"); }
  virtual uintm *getDefaultValue(void) {
    throw LowlevelError("getDefaultValue should not be called for GHIDRA"); }
public:
  ContextGhidra(ArchitectureGhidra *g) { glb = g; }	///< Construct with a specific client
  virtual ~ContextGhidra(void) {}

  // Routines that are actually implemented
  virtual const TrackedSet &getTrackedSet(const Address &addr) const;

  // Ignored routines (taken care of by GHIDRA)
  virtual void restoreXml(const Element *el,const AddrSpaceManager *manage) {}
  virtual void restoreFromSpec(const Element *el,const AddrSpaceManager *manage) {}

  // Unimplemented routines (should never be called)
  virtual int getContextSize(void) const {
    throw LowlevelError("getContextSize should not be called for GHIDRA"); }
  virtual const uintm *getContext(const Address &addr) const {
    throw LowlevelError("getContext should not be called for GHIDRA"); }
  virtual const uintm *getContext(const Address &addr,uintb &first,uintb &last) const {
    throw LowlevelError("getContext should not be called for GHIDRA"); }
  virtual void registerVariable(const string &nm,int4 sbit,int4 ebit) {
    throw LowlevelError("registerVariable should not be called for GHIDRA"); }
  virtual void saveXml(ostream &s) const {
    throw LowlevelError("context::saveXml should not be called for GHIDRA"); }

  virtual TrackedSet &createSet(const Address &addr1,const Address &addr2) {
    throw LowlevelError("createSet should not be called for GHIDRA"); }
  virtual TrackedSet &getTrackedDefault(void) {
    throw LowlevelError("getTrackedDefault should not be called for GHIDRA"); }
};

#endif
