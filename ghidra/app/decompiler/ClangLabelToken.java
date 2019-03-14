/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.decompiler;

import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

public class ClangLabelToken extends ClangToken {
	private Address blockaddr;	// Address this is labelling
	
	public ClangLabelToken(ClangNode par) {
		super(par);
		blockaddr = null;
	}
	
	@Override
    public boolean isVariableRef() { return false; }
	
	@Override
    public Address getMinAddress() { return blockaddr; }
	
	@Override
    public Address getMaxAddress() { return blockaddr; }
	
	@Override
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el, end, pfactory);
		String name = el.getAttribute(ClangXML.SPACE);
		AddressSpace spc = pfactory.getAddressFactory().getAddressSpace(name);
		long offset = SpecXmlUtils.decodeLong(el.getAttribute(ClangXML.OFFSET));
		blockaddr = spc.getAddress(offset);
	}

	
}
