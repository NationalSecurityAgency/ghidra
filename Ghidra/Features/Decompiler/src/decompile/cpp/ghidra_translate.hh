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
/// \file ghidra_translate.hh
/// \brief Class for fetching p-code from a Ghidra client

#ifndef __TRANSLATE_GHIDRA__
#define __TRANSLATE_GHIDRA__

#include "translate.hh"
#include "ghidra_arch.hh"

/// \brief An implementation of Translate that queries a Ghidra client for p-code information
///
/// This class provides:
///   - P-code for instructions and
///   - Register names
///
/// by sending a request to a Ghidra client and decoding the response.
/// Messages are generally based on an XML format, but p-code responses in particular
/// have a tight internal encoding.
class GhidraTranslate : public Translate {
  ArchitectureGhidra *glb;			///< The Ghidra Architecture and connection to the client
  mutable map<string,VarnodeData> nm2addr;	///< Mapping from register name to Varnode
  mutable map<VarnodeData,string> addr2nm;	///< Mapping rom Varnode to register name
  const VarnodeData &cacheRegister(const string &nm,const VarnodeData &data) const;
  void restoreXml(const Element *el);		///< Initialize \b this Translate from XML
public:
  GhidraTranslate(ArchitectureGhidra *g) { glb = g; }	///< Constructor

  virtual void initialize(DocumentStorage &store);
  virtual const VarnodeData &getRegister(const string &nm) const;
  virtual string getRegisterName(AddrSpace *base,uintb off,int4 size) const;
  virtual void getAllRegisters(map<VarnodeData,string> &reglist) const {
    throw LowlevelError("Cannot currently get all registers through this interface"); }
  virtual void getUserOpNames(vector<string> &res) const;
  virtual int4 oneInstruction(PcodeEmit &emit,const Address &baseaddr) const;
  virtual int4 instructionLength(const Address &baseaddr) const {
    throw LowlevelError("Cannot currently get instruction length through this interface"); }
  virtual int4 printAssembly(AssemblyEmit &emit,const Address &baseaddr) const {
    throw LowlevelError("Cannot dump assembly through this interface"); }
};

#endif
