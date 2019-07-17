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
#include "loadimage_ghidra.hh"

LoadImageGhidra::LoadImageGhidra(ArchitectureGhidra *g)
  : LoadImage("ghidra_progam")

{
  glb = g;
}

void LoadImageGhidra::open(void)

{
}

void LoadImageGhidra::close(void)

{
}

void LoadImageGhidra::loadFill(uint1 *ptr,int4 size,const Address &inaddr)

{
  glb->getBytes(ptr,size,inaddr);
}

string LoadImageGhidra::getArchType(void) const

{
  return "ghidra";
}

void LoadImageGhidra::adjustVma(long adjust)

{
  throw LowlevelError("Cannot adjust GHIDRA virtual memory");
}
