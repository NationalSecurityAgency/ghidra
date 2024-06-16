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
#include "ghidra_context.hh"

namespace ghidra {

const TrackedSet &ContextGhidra::getTrackedSet(const Address &addr) const

{
  cache.clear();
  PackedDecode decoder(glb);
  glb->getTrackedRegisters(addr,decoder);

  uint4 elemId = decoder.openElement(ELEM_TRACKED_POINTSET);
  decodeTracked(decoder,cache);
  decoder.closeElement(elemId);
  return cache;
}

void ContextGhidra::decode(Decoder &decoder)

{
  decoder.skipElement();	// Ignore details handled by ghidra
}

void ContextGhidra::decodeFromSpec(Decoder &decoder)

{
  decoder.skipElement();	// Ignore details handled by ghidra
}

} // End namespace ghidra
