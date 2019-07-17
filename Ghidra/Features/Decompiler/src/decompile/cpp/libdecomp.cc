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
#include "libdecomp.hh"

void startDecompilerLibrary(const char *sleighhome)

{
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();

  if (sleighhome != (const char *)0)
    SleighArchitecture::scanForSleighDirectories(sleighhome);
}

void startDecompilerLibrary(const vector<string> &extrapaths)

{
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();

  for(uint4 i=0;i<extrapaths.size();++i)
    SleighArchitecture::specpaths.addDir2Path(extrapaths[i]);
}

void startDecompilerLibrary(const char *sleighhome,const vector<string> &extrapaths)

{
  CapabilityPoint::initializeAll();
  ArchitectureCapability::sortCapabilities();

  if (sleighhome != (const char *)0)
    SleighArchitecture::scanForSleighDirectories(sleighhome);

  for(uint4 i=0;i<extrapaths.size();++i)
    SleighArchitecture::specpaths.addDir2Path(extrapaths[i]);
}

void shutdownDecompilerLibrary(void)

{
}

