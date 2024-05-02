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
public class XmlEncode implements CachedEncoder {

	private static final int TAG_START = 0;		// Tag has been opened, attributes can be written
	private static final int TAG_CONTENT = 1;	// Opening tag and content have been written
	private static final int TAG_STOP = 2;		// No tag is currently being written

	private static final char[] spaces = { '\n', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' };
	private StringBuilder buffer;				// Buffer accumulating the document characters
	private int tagStatus;						// Stage of writing an element tag
	private int depth;							// Depth of open elements
	private boolean doFormatting;				// true if encoder should indent and emit newlines

	public XmlEncode() {
		buffer = new StringBuilder();
		tagStatus = TAG_STOP;
		depth = 0;
		doFormatting = true;
	}

	public XmlEncode(boolean doFormat) {
		buffer = new StringBuilder();
		tagStatus = TAG_STOP;
		depth = 0;
		doFormatting = doFormat;
	}

	private void newLine() {
		if (!doFormatting) {
			return;
		}
		int numSpaces = depth * 2 + 1;
		if (numSpaces > spaces.length) {
			numSpaces = spaces.length;
		}
		buffer.append(spaces, 0, numSpaces);
	}

	@Override
	public String toString() {
		return buffer.toString();
	}

	@Override
	public void clear() {
		buffer = new StringBuilder();
		tagStatus = TAG_STOP;
		depth = 0;
	}

	@Override
	public void openElement(ElementId elemId) throws IOException {
		if (tagStatus == TAG_START) {
			buffer.append('>');
		}
		else {
			tagStatus = TAG_START;
		}
		newLine();
		buffer.append('<');
		buffer.append(elemId.name());
		depth += 1;
	}

	@Override
	public void closeElement(ElementId elemId) throws IOException {
		depth -= 1;
		if (tagStatus == TAG_START) {
			buffer.append("/>");
			tagStatus = TAG_STOP;
			return;
		}
		if (tagStatus != TAG_CONTENT) {
			newLine();
		}
		else {
			tagStatus = TAG_STOP;
		}
		buffer.append("</");
		buffer.append(elemId.name());
		buffer.append('>');
	}

	@Override
	public void writeBool(AttributeId attribId, boolean val) throws IOException {
		if (attribId == ATTRIB_CONTENT) {	// Special id indicating, text value
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			buffer.append(val ? "true" : "false");
			tagStatus = TAG_CONTENT;
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
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			buffer.append(Long.toString(val, 10));
			tagStatus = TAG_CONTENT;
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
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			buffer.append("0x");
			buffer.append(Long.toHexString(val));
			tagStatus = TAG_CONTENT;
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
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			SpecXmlUtils.xmlEscape(buffer, val);
			tagStatus = TAG_CONTENT;
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
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			SpecXmlUtils.xmlEscape(buffer, spcName);
			tagStatus = TAG_CONTENT;
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		SpecXmlUtils.xmlEscape(buffer, spcName);
		buffer.append("\"");
	}

	@Override
	public void writeSpace(AttributeId attribId, int index, String name) throws IOException {
		if (attribId == ATTRIB_CONTENT) {
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			SpecXmlUtils.xmlEscape(buffer, name);
			tagStatus = TAG_CONTENT;
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		SpecXmlUtils.xmlEscape(buffer, name);
		buffer.append("\"");
	}

	@Override
	public void writeOpcode(AttributeId attribId, int opcode) throws IOException {
		String name = PcodeOp.getMnemonic(opcode);
		if (attribId == ATTRIB_CONTENT) {
			if (tagStatus == TAG_START) {
				buffer.append('>');
			}
			buffer.append(name);
			tagStatus = TAG_CONTENT;
			return;
		}
		buffer.append(' ');
		buffer.append(attribId.name());
		buffer.append("=\"");
		buffer.append(name);
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
