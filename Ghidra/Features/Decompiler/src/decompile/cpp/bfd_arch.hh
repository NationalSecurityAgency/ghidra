/* ###
 * IP: GHIDRA
 * NOTE: Interface to GNU BFD library which is GPL 3
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
/// \file bfd_arch.hh
/// \brief Specific implementation of Architecture using GNU BFD libraries
#ifndef __BFD_ARCH_HH__
#define __BFD_ARCH_HH__

#include "sleigh_arch.hh"
#include "loadimage_bfd.hh"

namespace ghidra {

extern ElementId ELEM_BFD_SAVEFILE;	///< Marshaling element \<bfd_savefile>

/// \brief Extension point for building a GNU BFD capable Architecture
class BfdArchitectureCapability : public ArchitectureCapability {
  static BfdArchitectureCapability bfdArchitectureCapability;		///< The singleton instance
  BfdArchitectureCapability(void);					///< Singleton constructor
  BfdArchitectureCapability(const BfdArchitectureCapability &op2);	///< Not implemented
  BfdArchitectureCapability &operator=(const BfdArchitectureCapability &op2);	///< Not implemented
public:
  virtual ~BfdArchitectureCapability(void);
  virtual Architecture *buildArchitecture(const string &filename,const string &target,ostream *estream);
  virtual bool isFileMatch(const string &filename) const;
  virtual bool isXmlMatch(Document *doc) const;
};

/// \brief Architecture that reads executable files using GNU BFD libraries
class BfdArchitecture : public SleighArchitecture {
  long adjustvma;					///< How much to adjust the virtual memory address
  virtual void buildLoader(DocumentStorage &store);
  virtual void resolveArchitecture(void);
  virtual void postSpecFile(void);
public:
  virtual void encode(Encoder &encoder) const;
  virtual void restoreXml(DocumentStorage &store);
  BfdArchitecture(const string &fname,const string &targ,ostream *estream);	///< Constructor
  virtual ~BfdArchitecture(void) {}
};

} // End namespace ghidra
#endif
