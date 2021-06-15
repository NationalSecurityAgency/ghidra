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
/// \file string_ghidra.hh
/// \brief Implementation of the StringManager through the ghidra client

#ifndef __STRING_GHIDRA__
#define __STRING_GHIDRA__

#include "ghidra_arch.hh"

/// \brief Implementation of the StringManager that queries through the ghidra client
///
/// This acts as a front end to Ghidra's string formats and encodings.
/// The client translates any type of string into a UTF8 representation, and this
/// class stores it for final presentation.  Escaping the UTF8 string is left up
/// to the PrintLanguage.
class GhidraStringManager : public StringManager {
  ArchitectureGhidra *glb;		///< The ghidra client interface
  uint1 *testBuffer;			///< Temporary storage for storing bytes from client
public:
  GhidraStringManager(ArchitectureGhidra *g,int4 max);	///< Constructor
  virtual ~GhidraStringManager(void);
  virtual const vector<uint1> &getStringData(const Address &addr,Datatype *charType,bool &isTrunc);
};

#endif
