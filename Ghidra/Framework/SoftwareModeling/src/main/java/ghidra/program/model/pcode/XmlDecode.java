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

import java.io.InputStream;
import java.util.Iterator;
import java.util.Map;

import org.xml.sax.*;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.Msg;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.*;

public class XmlDecode implements Decoder {

	private XmlPullParser parser;
	private XmlElement currentEl;
	private Iterator<Map.Entry<String, String>> attribIterator;
	private String attribValue;
	private AddressFactory spcManager;

	public XmlDecode(AddressFactory factory) {
		parser = null;
		currentEl = null;
		attribIterator = null;
		attribValue = null;
		spcManager = factory;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return spcManager;
	}

	@Override
	public void clear() {
		parser = null;
		currentEl = null;
		attribIterator = null;
	}

	@Override
	public void ingestStream(InputStream stream, String source) throws PcodeXMLException {
		ErrorHandler handler = new ErrorHandler() {
			@Override
			public void error(SAXParseException exception) throws SAXException {
				Msg.error(this, "Error parsing " + source, exception);
			}

			@Override
			public void fatalError(SAXParseException exception) throws SAXException {
				Msg.error(this, "Fatal error parsing " + source, exception);
			}

			@Override
			public void warning(SAXParseException exception) throws SAXException {
				Msg.warn(this, "Warning parsing " + source, exception);
			}
		};
		try {
			parser = XmlPullParserFactory.create(stream, source, handler, false);
		}
		catch (Exception e) {
			throw new PcodeXMLException("XML parsing error: " + e.getMessage(), e);
		}
	}

	@Override
	public int peekElement() {
		XmlElement el = parser.peek();
		if (!el.isStart()) {
			return 0;
		}
		return ElementId.find(el.getName());
	}

	@Override
	public int openElement() {
		XmlElement el = parser.softStart();
		if (el == null) {
			return 0;
		}
		currentEl = el;
		attribIterator = null;
		return ElementId.find(currentEl.getName());
	}

	@Override
	public int openElement(ElementId elemId) throws PcodeXMLException {
		XmlElement el = parser.softStart(elemId.name());
		if (el == null) {
			throw new PcodeXMLException("Expecting element <" + elemId.name() + '>');
		}
		currentEl = el;
		attribIterator = null;
		return ElementId.find(currentEl.getName());
	}

	@Override
	public void closeElement(int id) throws PcodeXMLException {
		XmlElement el = parser.next();
		if (!el.isEnd()) {
			throw new PcodeXMLException("Expecting end, but got start <" + el.getName() + '>');
		}
		currentEl = null;
		// Only one possible element can be closed as enforced by SAXParser
		// so additional checks are somewhat redundant
//		int elemId = ElementId.find(el.getName());
//		if (elemId != id) {
//			throw new PcodeXMLException("Unexpected end, <" + el.getName() + '>');
//		}
	}

	@Override
	public void closeElementSkipping(int id) throws PcodeXMLException {
		currentEl = null;
		XmlElement el = parser.peek();
		if (el == null) {
			throw new PcodeXMLException("No more elements");
		}
		int level = el.getLevel();
		if (el.isStart()) {
			level -= 1;
		}
		for (;;) {
			el = parser.next();
			int curlevel = el.getLevel();
			if (curlevel > level) {
				continue;
			}
			if (curlevel < level) {
				throw new PcodeXMLException("Missing end element");
			}
			if (el.isEnd()) {
				break;
			}
		}
		int elemId = ElementId.find(el.getName());
		if (elemId != id) {
			throw new PcodeXMLException("Unexpected element end: " + el.getName());
		}
	}

	@Override
	public int getNextAttributeId() {
		if (attribIterator == null) {
			attribIterator = currentEl.getAttributeIterator();
		}
		if (!attribIterator.hasNext()) {
			return 0;
		}
		Map.Entry<String, String> entry = attribIterator.next();
		attribValue = entry.getValue();
		return AttributeId.find(entry.getKey());
	}

	@Override
	public void rewindAttributes() {
		attribIterator = null;
	}

	private String readContent() throws PcodeXMLException {
		XmlElement el = parser.peek();
		if (el == null || !el.isEnd()) {
			throw new PcodeXMLException("Cannot request ATTRIB_CONTENT here");
		}
		return el.getText();
	}

	@Override
	public boolean readBool() throws PcodeXMLException {
		return SpecXmlUtils.decodeBoolean(attribValue);
	}

	@Override
	public boolean readBool(AttributeId attribId) throws PcodeXMLException {
		String value;
		if (attribId == ATTRIB_CONTENT) {
			value = readContent();
		}
		else {
			value = currentEl.getAttribute(attribId.name());
		}
		if (value == null) {
			throw new PcodeXMLException("Missing attribute: " + attribId.name());
		}
		attribIterator = null;
		return SpecXmlUtils.decodeBoolean(value);
	}

	@Override
	public long readSignedInteger() throws PcodeXMLException {
		return SpecXmlUtils.decodeLong(attribValue);
	}

	@Override
	public long readSignedInteger(AttributeId attribId) throws PcodeXMLException {
		String value;
		if (attribId == ATTRIB_CONTENT) {
			value = readContent();
		}
		else {
			value = currentEl.getAttribute(attribId.name());
		}
		if (value == null) {
			throw new PcodeXMLException("Missing attribute: " + attribId.name());
		}
		attribIterator = null;
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public long readUnsignedInteger() throws PcodeXMLException {
		return SpecXmlUtils.decodeLong(attribValue);
	}

	@Override
	public long readUnsignedInteger(AttributeId attribId) throws PcodeXMLException {
		String value;
		if (attribId == ATTRIB_CONTENT) {
			value = readContent();
		}
		else {
			value = currentEl.getAttribute(attribId.name());
		}
		if (value == null) {
			throw new PcodeXMLException("Missing attribute: " + attribId.name());
		}
		attribIterator = null;
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public String readString() throws PcodeXMLException {
		return attribValue;
	}

	@Override
	public String readString(AttributeId attribId) throws PcodeXMLException {
		String value;
		if (attribId == ATTRIB_CONTENT) {
			value = readContent();
		}
		else {
			value = currentEl.getAttribute(attribId.name());
		}
		if (value == null) {
			throw new PcodeXMLException("Missing attribute: " + attribId.name());
		}
		attribIterator = null;
		return value;
	}

	@Override
	public AddressSpace readSpace() throws PcodeXMLException {
		return spcManager.getAddressSpace(attribValue);
	}

	@Override
	public AddressSpace readSpace(AttributeId attribId) throws PcodeXMLException {
		String value;
		if (attribId == ATTRIB_CONTENT) {
			value = readContent();
		}
		else {
			value = currentEl.getAttribute(attribId.name());
		}
		if (value == null) {
			throw new PcodeXMLException("Missing attribute: " + attribId.name());
		}
		attribIterator = null;
		return spcManager.getAddressSpace(value);
	}

}
