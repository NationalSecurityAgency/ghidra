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
/// \file cpool_ghidra.hh
/// \brief Utility for implementing a \e constant \e pool backed by a Ghidra client

#ifndef __CPOOL_GHIDRA_HH__
#define __CPOOL_GHIDRA_HH__

#include "ghidra_arch.hh"

namespace ghidra {

/// \brief An implementation of ConstantPool using a Ghidra client as the backing storage
///
/// The actual CPoolRecord objects are cached locally, but new queries are placed
/// with the Ghidra client hosting the program currently being decompiled. The
/// queries and response records are sent via XML.  The encode() and decode()
/// methods are disabled.  The clear() method only releases the local cache,
/// no records on the Ghidra client are affected.
class ConstantPoolGhidra : public ConstantPool {
  ArchitectureGhidra *ghidra;			///< The connection with the Ghidra client
  mutable ConstantPoolInternal cache;		///< The local cache of previouly queried CPoolRecord objects
  virtual CPoolRecord *createRecord(const vector<uintb> &refs);
public:
  ConstantPoolGhidra(ArchitectureGhidra *g);	///< Constructor
  virtual const CPoolRecord *getRecord(const vector<uintb> &refs) const;
  virtual bool empty(void) const { return false; }
  virtual void clear(void) { cache.clear(); }
  virtual void encode(Encoder &encoder) const;
  virtual void decode(Decoder &decoder,TypeFactory &typegrp);
};

} // End namespace ghidra
#endif
