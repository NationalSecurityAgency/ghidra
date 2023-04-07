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
/// \file capability.hh
/// \brief Infrastructure for discovering code extensions to the decompiler
#ifndef __CAPABILITY_HH__
#define __CAPABILITY_HH__

#include "types.h"
#include <vector>
#include <string>

namespace ghidra {

using std::vector;
using std::string;

/// \brief Class for automatically registering extension points to the decompiler
///
/// This uses the C++ static initializer feature to automatically \e discover
/// and register extension point. Code for an extension should provide
/// a class that derives from CapabilityPoint and overrides the initialize() method.
/// Additionally there should be a singleton static instantiation of this extension class.
/// The extensions are accumulated in a list automatically, then the decompiler engine
/// will ensure that the initialize() method is called on each extension, allowing it
/// to complete its integration.
class CapabilityPoint {
  static vector<CapabilityPoint *> &getList(void);	///< Retrieve the list of extension point singletons
protected:
  CapabilityPoint(void);		///< Construct extension capability exactly once
public:
  virtual ~CapabilityPoint(void) {}	///< Destructor

  /// \brief Complete initialization of an extension point
  ///
  /// This method is implemented by each extension so it can do specialized integration
  virtual void initialize(void)=0;

  static void initializeAll(void);	///< Finish initialization for all extension points
};

} // End namespace ghidra
#endif
