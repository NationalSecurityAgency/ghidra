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

/// Build this VarnodeData from an \b \<addr\> tag
/// \param el is the parsed tag
/// \param manage is the address space manager
void VarnodeData::restoreXml(const Element *el,const AddrSpaceManager *manage)

{
  space = (AddrSpace *)0;
  size = 0;
  int4 num = el->getNumAttributes();
  for(int4 i=0;i<num;++i) {
    if (el->getAttributeName(i)=="space") {
      space = manage->getSpaceByName(el->getAttributeValue(i));
      if (space == (AddrSpace *)0)
	throw LowlevelError("Unknown space name: "+el->getAttributeValue(i));
      offset = space->restoreXmlAttributes(el,size);
      return;
    }
    else if (el->getAttributeName(i)=="name") {
      const Translate *trans = manage->getDefaultCodeSpace()->getTrans();
      const VarnodeData &point(trans->getRegister(el->getAttributeValue(i)));
      *this = point;
      return;
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
