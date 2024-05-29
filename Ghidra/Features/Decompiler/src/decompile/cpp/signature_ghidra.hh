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
/// \file signature_ghidra.hh
/// \brief Feature/Signature generation commands that can be issued to the decompiler by the Ghidra client
#ifndef __GHIDRA_SIGNATURES_HH__
#define __GHIDRA_SIGNATURES_HH__

#include "ghidra_process.hh"

namespace ghidra {

/// \brief Signature command capability
///
/// This class is instantiated as a singleton and registers commands that the Ghidra client can issue
/// for generating feature vectors extracted from decompiled functions.
class GhidraSignatureCapability : public GhidraCapability {
  static GhidraSignatureCapability ghidraSignatureCapability;			///< Singleton instance
  GhidraSignatureCapability(void) { name = "signature"; }			///< Construct the singleton instance
  GhidraSignatureCapability(const GhidraSignatureCapability &op2);		///< Not implemented
  GhidraSignatureCapability &operator=(const GhidraSignatureCapability &op2);	///< Not implemented
public:
  virtual void initialize(void);
};

/// \brief Command to generate a feature vector from a function's data-flow and control-flow graphs
///
/// The command expects to receive the entry point address of a function.  The function is
/// decompiled using the "normalize" simplification style.  Then features are extracted from the
/// resulting data-flow and control-flow graphs of the decompiled function.  The features are
/// returned to the Ghidra client.  The command can be instantiated in two forms. One form returns
/// a stream-lined encoding of the feature vector for more efficient transfers during normal operation.
/// The other form returns more descriptive meta-data with the features and is suitable for debugging
/// or exploring the feature generation process.
class SignaturesAt : public GhidraCommand {
  bool debug;						///< True if the command should return verbose feature encodings
  Address addr;						///< The entry point of the function to generate features for
  virtual void loadParameters(void);
public:
  SignaturesAt(bool dbg) { debug = dbg; }		///< Constructor specifying response format
  virtual void rawAction(void);
};

/// \brief Command to retrieve current decompiler settings being used for feature/signature generation
///
/// The command returns an opaque integer indicating the state of boolean properties affecting
/// feature generation.  The reserved value of 0 indicates that no settings have been provided to the
/// decompiler process.
class GetSignatureSettings : public GhidraCommand {
public:
  virtual void rawAction(void);
};

/// \brief Command to provide the global settings used by the decompiler process during feature/signature generation
///
/// The command expects to receive an opaque integer value encoding the state of boolean properties affecting
/// feature generation.  The command returns 't' indicating a valid setting was received or 'f' for an invalid setting.
class SetSignatureSettings : public GhidraCommand {
  uint4 settings;			///< Opaque settings value being requested
  virtual void loadParameters(void);
public:
  virtual void rawAction(void);
};

} // End namespace ghidra
#endif
