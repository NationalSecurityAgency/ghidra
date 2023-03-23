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
package ghidra.program.model.pcode;

import static ghidra.program.model.pcode.AttributeId.*;

import java.io.IOException;
import java.io.OutputStream;

import ghidra.program.model.address.AddressSpace;
import ghidra.util.xml.SpecXmlUtils;

/**
 * An XML based encoder
 * The underlying transfer encoding is an XML document.
 * The encoder is initialized with a StringBuilder which will receive the XML document as calls
 * are made on the encoder.
 */
public class XmlEncode implements Encoder {

	private StringBuilder buffer;
	private boolean elementTagIsOpen;

	public XmlEncode() {
		buffer = new StringBuilder();
		elementTagIsOpen = false;
	}

	@Override
	public String toString() {
		return buffer.toString();
	}

	@Override
	public void clear() {
		buffer = new StringBuilder();
		elementTagIsOpen = false;
	}

	@Override
	public void openElement(ElementId elemId) throws IOException {
		if (elementTagIsOpen) {
			buffer.append('>');
		}
		else {
			elementTagIsOpen = true;
		}
		buffer.append('<');
		buffer.append(elemId.name());
	}

	@Override
	public void closeElement(ElementId elemId) throws IOException {
		if (elementTagIsOpen) {
			buffer.append("/>");
			elementTagIsOpen = false;
		}
		else {
			buffer.append("</");
			buffer.append(elemId.name());
			buffer.append('>');
		}
	}

	@Override
	public void writeBool(AttributeId attribId, boolean val) throws IOException {
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (elementTagIsOpen) {
				buffer.append('>');
				elementTagIsOpen = false;
			}
			buffer.append(val ? "true" : "false");
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		buffer.append(val ? "true" : "false");
		buffer.append("\"");
	}

	@Override
	public void writeSignedInteger(AttributeId attribId, long val) throws IOException {
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (elementTagIsOpen) {
				buffer.append('>');
				elementTagIsOpen = false;
			}
			buffer.append(Long.toString(val, 10));
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		buffer.append(Long.toString(val, 10));
		buffer.append("\"");
	}

	@Override
	public void writeUnsignedInteger(AttributeId attribId, long val) throws IOException {
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (elementTagIsOpen) {
				buffer.append('>');
				elementTagIsOpen = false;
			}
			buffer.append("0x");
			buffer.append(Long.toHexString(val));
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"0x");
		buffer.append(Long.toHexString(val));
		buffer.append("\"");
	}

	@Override
	public void writeString(AttributeId attribId, String val) throws IOException {
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (elementTagIsOpen) {
				buffer.append('>');
				elementTagIsOpen = false;
			}
			SpecXmlUtils.xmlEscape(buffer, val);
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		SpecXmlUtils.xmlEscape(buffer, val);
		buffer.append("\"");
	}

	@Override
	public void writeStringIndexed(AttributeId attribId, int index, String val) throws IOException {
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append(index + 1);
		buffer.append("=\"");
		SpecXmlUtils.xmlEscape(buffer, val);
		buffer.append("\"");
	}

	@Override
	public void writeSpace(AttributeId attribId, AddressSpace spc) throws IOException {
		String spcName;
		if (spc.getType() == AddressSpace.TYPE_VARIABLE) {
			spcName = "join";
		}
		else {
			spcName = spc.getName();
		}
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (elementTagIsOpen) {
				buffer.append('>');
				elementTagIsOpen = false;
			}
			SpecXmlUtils.xmlEscape(buffer, spcName);
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		SpecXmlUtils.xmlEscape(buffer, spcName);
		buffer.append("\"");
	}

	@Override
	public void writeTo(OutputStream stream) throws IOException {
		byte[] res = buffer.toString().getBytes();
		stream.write(res);
	}

	@Override
	public boolean isEmpty() {
		return buffer.isEmpty();
	}
}
