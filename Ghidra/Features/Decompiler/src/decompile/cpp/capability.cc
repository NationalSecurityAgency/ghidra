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
#include "capability.hh"

/// Access static vector of CapabilityPoint objects that are registered during static initialization
/// The list itself is created once on the first call to this method
/// \e after all the static initializers have run
/// \return the list of registered extensions
vector<CapabilityPoint *> &CapabilityPoint::getList(void)

{
  static vector<CapabilityPoint *> thelist;	// This gets allocated exactly once on first call
  return thelist;
}

/// Constructing the object automatically registers it.
/// For global instances, this happens during static initialization
CapabilityPoint::CapabilityPoint(void)

{
  getList().push_back(this);
}

/// Give all registered capabilities a chance to initialize (\e after all static initialization has happened)
void CapabilityPoint::initializeAll(void)

{
  vector<CapabilityPoint *> &list( getList() );
  for(int4 i=0;i<list.size();++i) {
    CapabilityPoint *ptr = list[i];
    ptr->initialize();
  }
  list.clear();
}

