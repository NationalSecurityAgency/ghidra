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
/// \file loadimage_ghidra.hh
/// \brief Use the Ghidra client as a load image
#ifndef __LOADIMAGE_GHIDRA__
#define __LOADIMAGE_GHIDRA__

#include "loadimage.hh"
#include "ghidra_arch.hh"

class ArchitectureGhidra;

/// \brief An implementation of the LoadImage interface using a Ghidra client as the back-end
///
/// Requests for program bytes are marshaled to a Ghidra client which sends back the data
class LoadImageGhidra : public LoadImage {
  ArchitectureGhidra *glb;			///< The owning Architecture and connection to the client
public:
  LoadImageGhidra(ArchitectureGhidra *g);	///< Constructor
  //  virtual ~LoadImage(void) {}
  void open(void);				///< Open any descriptors
  void close(void);				///< Close any descriptor
  virtual void loadFill(uint1 *ptr,int4 size,const Address &addr);
  // Read only flags are all controlled through the database interface
  virtual string getArchType(void) const;
  virtual void adjustVma(long adjust);
};

#endif
