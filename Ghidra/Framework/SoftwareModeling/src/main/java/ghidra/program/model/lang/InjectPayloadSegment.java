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
package ghidra.program.model.lang;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.AddressXML;
import ghidra.program.model.pcode.Encoder;
import ghidra.util.SystemUtilities;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class InjectPayloadSegment extends InjectPayloadSleigh {

	private AddressSpace space;
	private boolean supportsFarPointer;
	private AddressSpace constResolveSpace;
	private long constResolveOffset;
	private int constResolveSize;

	public InjectPayloadSegment(String source) {
		super(source);
		type = EXECUTABLEPCODE_TYPE;
		space = null;
		supportsFarPointer = false;
		constResolveSpace = null;
		constResolveOffset = 0;
		constResolveSize = 0;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_SEGMENTOP);
		int pos = name.indexOf('_');
		String subName = pos > 0 ? name.substring(0, pos) : name;
		if (!subName.equals("segment")) {
			encoder.writeString(ATTRIB_USEROP, subName);
		}
		encoder.writeSpace(ATTRIB_SPACE, space);
		if (supportsFarPointer) {
			encoder.writeBool(ATTRIB_FARPOINTER, supportsFarPointer);
		}
		super.encode(encoder);
		if (constResolveSpace != null) {
			encoder.openElement(ELEM_CONSTRESOLVE);
			encoder.openElement(ELEM_VARNODE);
			encoder.writeSpace(ATTRIB_SPACE, constResolveSpace);
			encoder.writeUnsignedInteger(ATTRIB_OFFSET, constResolveOffset);
			encoder.writeSignedInteger(ATTRIB_SIZE, constResolveSize);
			encoder.closeElement(ELEM_VARNODE);
			encoder.closeElement(ELEM_CONSTRESOLVE);
		}
		encoder.closeElement(ELEM_SEGMENTOP);
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language) throws XmlParseException {
		XmlElement el = parser.start();
		name = el.getAttribute("userop");
		if (name == null) {
			name = "segment";
		}
		name = name + "_pcode";
		String spaceString = el.getAttribute("space");
		space = language.getAddressFactory().getAddressSpace(spaceString);
		if (space == null) {
			throw new XmlParseException("Unknown address space: " + spaceString);
		}
		supportsFarPointer = SpecXmlUtils.decodeBoolean(el.getAttribute("farpointer"));
		if (parser.peek().isStart()) {
			if (parser.peek().getName().equals("pcode")) {
				super.restoreXml(parser, language);
			}
			else {
				throw new XmlParseException("Missing <pcode> child for <segmentop> tag");
			}
		}
		if (parser.peek().isStart()) {
			XmlElement subel = parser.start("constresolve");
			XmlElement subsubel = parser.start();
			AddressXML addrSize = AddressXML.restoreXml(subsubel, language);
			addrSize.getFirstAddress();		// Fail fast. Throws AddressOutOfBoundsException if offset is invalid
			constResolveSpace = addrSize.getAddressSpace();
			constResolveOffset = addrSize.getOffset();
			constResolveSize = (int) addrSize.getSize();
			parser.end(subsubel);
			parser.end(subel);
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadSegment op2 = (InjectPayloadSegment) obj;
		if (constResolveOffset != op2.constResolveOffset) {
			return false;
		}
		if (constResolveSize != op2.constResolveSize) {
			return false;
		}
		if (!SystemUtilities.isEqual(constResolveSpace, op2.constResolveSpace)) {
			return false;
		}
		if (!space.equals(op2.space)) {
			return false;
		}
		if (supportsFarPointer != op2.supportsFarPointer) {
			return false;
		}
		return super.isEquivalent(obj);
	}
}
