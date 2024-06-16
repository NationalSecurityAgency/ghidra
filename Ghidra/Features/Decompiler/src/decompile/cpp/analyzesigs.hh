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
/// \file analyzesigs.hh
/// \brief Commands for feature/signature generation from the console interface
#ifndef __ANALYZESIGS_HH__
#define __ANALYZESIGS_HH__

#include "codedata.hh"
#include "signature.hh"

namespace ghidra {

/// \brief Interface capability point for console commands associated with signature/feature generation
class IfaceAnalyzeSigsCapability : public IfaceCapability {
  static IfaceAnalyzeSigsCapability ifaceAnalyzeSigsCapability; 	///< Singleton instance
  IfaceAnalyzeSigsCapability(void);						///< Construct the singleton
  IfaceAnalyzeSigsCapability(const IfaceAnalyzeSigsCapability &op2); 		///< Not implemented
  IfaceAnalyzeSigsCapability &operator=(const IfaceAnalyzeSigsCapability &op2); ///< Not implemented
public:
  virtual void registerCommands(IfaceStatus *status);
};

class IfcSignatureSettings : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcPrintSignatures : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSaveSignatures : public IfaceDecompCommand {
public:
  virtual void execute(istream &s);
};

class IfcSaveAllSignatures : public IfaceDecompCommand {
protected:
  GraphSigManager *smanage;	///< Manager for generating signatures
public:
  IfcSaveAllSignatures(void) { smanage = (GraphSigManager *)0; }	///< Constructor
  virtual ~IfcSaveAllSignatures(void) { if (smanage != (GraphSigManager *)0) delete smanage; }
  virtual void execute(istream &s);
  virtual void iterationCallback(Funcdata *fd);
};

class IfcProduceSignatures : public IfcSaveAllSignatures {
public:
  virtual void iterationCallback(Funcdata *fd);
};

} // End namespace ghidra
#endif
