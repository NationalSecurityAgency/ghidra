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

namespace ghidra {

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

/// This assumes the \<op> element is already open.
/// Decode info suitable for call to PcodeEmit::dump.  The output pointer is changed to null if there
/// is no output for this op, otherwise the existing pointer is used to store the output.
/// \param decoder is the stream decoder
/// \param isize is the (preparsed) number of input parameters for the p-code op
/// \param invar is an array of storage for the input Varnodes
/// \param outvar is a (handle) to the storage for the output Varnode
/// \return the p-code op OpCode
OpCode PcodeOpRaw::decode(Decoder &decoder,int4 isize,VarnodeData *invar,VarnodeData **outvar)

{
  OpCode opcode = (OpCode)decoder.readSignedInteger(ATTRIB_CODE);
  uint4 subId = decoder.peekElement();
  if (subId == ELEM_VOID) {
    decoder.openElement();
    decoder.closeElement(subId);
    *outvar = (VarnodeData *)0;
  }
  else {
    (*outvar)->decode(decoder);
  }
  for(int4 i=0;i<isize;++i) {
    subId = decoder.peekElement();
    if (subId == ELEM_SPACEID) {
      decoder.openElement();
      invar[i].space = decoder.getAddrSpaceManager()->getConstantSpace();
      invar[i].offset = (uintb)(uintp)decoder.readSpace(ATTRIB_NAME);
      invar[i].size = sizeof(void *);
      decoder.closeElement(subId);
    }
    else
      invar[i].decode(decoder);
  }
  return opcode;
}

} // End namespace ghidra
