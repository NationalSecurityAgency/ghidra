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
package ghidra.app.decompiler;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeFactory;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;

public class ClangCommentToken extends ClangToken {

	private Address srcaddr;	// source address of the comment

	public static ClangCommentToken derive(ClangCommentToken source, String text) {

		ClangCommentToken newToken = new ClangCommentToken(source.Parent());

		newToken.setText(text);
		newToken.setLineParent(source.getLineParent());
		newToken.setSyntaxType(source.getSyntaxType());
		newToken.setHighlight(source.getHighlight());
		newToken.srcaddr = source.srcaddr;
		return newToken;
	}

	public ClangCommentToken(ClangNode par) {
		super(par);
		srcaddr = null;
	}

	@Override
	public boolean isVariableRef() {
		return false;
	}

	@Override
	public Address getMinAddress() {
		return srcaddr;
	}

	@Override
	public Address getMaxAddress() {
		return srcaddr;
	}

	@Override
	public void restoreFromXML(XmlElement el, XmlElement end, PcodeFactory pfactory) {
		super.restoreFromXML(el, end, pfactory);
		String name = el.getAttribute(ClangXML.SPACE);
		AddressSpace spc = pfactory.getAddressFactory().getAddressSpace(name);
		long offset = SpecXmlUtils.decodeLong(el.getAttribute(ClangXML.OFFSET));
		srcaddr = spc.getAddress(offset);
	}

}
