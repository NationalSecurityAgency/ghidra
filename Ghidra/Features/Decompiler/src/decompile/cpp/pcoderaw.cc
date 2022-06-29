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
#include "pcoderaw.hh"
#include "translate.hh"

/// Build this VarnodeData from an \<addr>, \<register>, or \<varnode> element.
/// \param decoder is the stream decoder
void VarnodeData::decode(Decoder &decoder)

{
  uint4 elemId = decoder.openElement();
  decodeFromAttributes(decoder);
  decoder.closeElement(elemId);
}

/// Collect attributes for the VarnodeData possibly from amidst other attributes
/// \param decoder is the stream decoder
void VarnodeData::decodeFromAttributes(Decoder &decoder)

{
  space = (AddrSpace *)0;
  size = 0;
  for(;;) {
    uint4 attribId = decoder.getNextAttributeId();
    if (attribId == 0)
      break;		// Its possible to have no attributes in an <addr/> tag
    if (attribId == ATTRIB_SPACE) {
      space = decoder.readSpace();
      decoder.rewindAttributes();
      offset = space->decodeAttributes(decoder,size);
      break;
    }
    else if (attribId == ATTRIB_NAME) {
      const Translate *trans = decoder.getAddrSpaceManager()->getDefaultCodeSpace()->getTrans();
      const VarnodeData &point(trans->getRegister(decoder.readString()));
      *this = point;
      break;
    }
  }
}

/// Return \b true, if \b this, as an address range, contains the other address range
/// \param op2 is the other VarnodeData to test for containment
/// \return \b true if \b this contains the other
bool VarnodeData::contains(const VarnodeData &op2) const

{
  if (space != op2.space) return false;
  if (op2.offset < offset) return false;
  if ((offset + (size-1)) < (op2.offset + (op2.size-1))) return false;
  return true;
}
