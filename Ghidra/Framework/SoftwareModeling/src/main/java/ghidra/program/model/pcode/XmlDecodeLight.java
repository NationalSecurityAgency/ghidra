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

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.xml.SpecXmlUtils;

/**
 * Lightweight XML decoder.
 *   - Element and attribute identifiers must contain only letters or digits
 *   - No XML comments
 *   - No escape codes
 *   - No content (except white space)
 */
public class XmlDecodeLight implements Decoder {

	private AddressFactory addressFactory;
	private String raw;
	private int currentPos;
	private boolean startOpen;
	private int attribStart;
	private int currentElement;

	public XmlDecodeLight(AddressFactory addrFactory) {
		addressFactory = addrFactory;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	@Override
	public void clear() {
		raw = null;
	}

	public void ingestString(String data) {
		raw = data;
		currentPos = 0;
		startOpen = false;
		attribStart = -1;
	}

	private int scanWhiteSpace(int start) throws PcodeXMLException {
		while (start < raw.length()) {
			char tok = raw.charAt(start);
			if (!Character.isWhitespace(tok)) {
				return start;
			}
			start += 1;
		}
		throw new PcodeXMLException("Premature end of stream");
	}

	private int scanIdentifier(int start) throws PcodeXMLException {
		while (start < raw.length()) {
			char tok = raw.charAt(start);
			if (!Character.isLetterOrDigit(tok)) {
				return start;
			}
			start += 1;
		}
		throw new PcodeXMLException("Premature end of stream");
	}

	private int scanToEndOfStart(int start) throws PcodeXMLException {
		int state = 0;
		while (start < raw.length()) {
			char tok = raw.charAt(start);
			if (state == 0) {
				if (tok == '/' || tok == '>') {
					return start;
				}
				if (tok == '\"') {
					state = 1;
				}
			}
			else if (state == 1) {
				if (tok == '\"') {
					state = 0;
				}
			}
			start += 1;
		}
		throw new PcodeXMLException("Premature end of stream");
	}

	private String scanElement() throws PcodeXMLException {
		int pos = currentPos;
		if (startOpen) {
			pos = scanToEndOfStart(pos);
			if (raw.charAt(pos) == '>') {
				pos += 1;
			}
		}
		pos = scanWhiteSpace(pos);
		if (raw.charAt(pos) != '<') {
			throw new PcodeXMLException("Expecting start of element");
		}
		pos += 1;
		if (pos < raw.length() && raw.charAt(pos) == '/') {
			return null;
		}
		pos = scanWhiteSpace(pos);
		int endPos = scanIdentifier(pos);
		if (pos == endPos) {
			throw new PcodeXMLException("Parse error");
		}
		currentPos = endPos;
		startOpen = true;
		return raw.substring(pos, endPos);
	}

	private int scanQuote() throws PcodeXMLException {
		int pos = currentPos + 1;
		while (pos < raw.length()) {
			if (raw.charAt(pos) == '\"') {
				return pos + 1;
			}
			pos += 1;
		}
		throw new PcodeXMLException("Premature end of stream");
	}

	private String scanAttribute() throws PcodeXMLException {
		int pos = currentPos;
		currentPos = scanQuote();
		return raw.substring(pos + 1, currentPos - 1);
	}

	@Override
	public void ingestStream(InputStream stream, String source) throws PcodeXMLException {
		throw new PcodeXMLException("Unimplemented method");
	}

	@Override
	public int peekElement() {
		int savePos = currentPos;
		boolean saveStartOpen = startOpen;
		String el;
		try {
			el = scanElement();
			currentPos = savePos;
			startOpen = saveStartOpen;
			if (el == null) {
				return 0;
			}
		}
		catch (PcodeXMLException e) {
			currentPos = savePos;
			startOpen = saveStartOpen;
			return 0;
		}
		return ElementId.find(el);
	}

	@Override
	public int openElement() {
		String el;
		try {
			el = scanElement();
			if (el == null) {
				return 0;
			}
		}
		catch (PcodeXMLException e) {
			return 0;
		}
		attribStart = currentPos;
		currentElement = ElementId.find(el);
		return currentElement;
	}

	@Override
	public int openElement(ElementId elemId) throws PcodeXMLException {
		String el = scanElement();
		if (el == null) {
			throw new PcodeXMLException("Expecting start of " + elemId.name());
		}
		attribStart = currentPos;
		currentElement = ElementId.find(el);
		if (currentElement != elemId.id()) {
			throw new PcodeXMLException("Expecting element " + elemId.name());
		}
		return currentElement;
	}

	@Override
	public void closeElement(int id) throws PcodeXMLException {
		int pos = currentPos;
		if (startOpen) {
			pos = scanToEndOfStart(currentPos);
			char tok = raw.charAt(pos);
			if (tok == '/') {
				pos += 1;
				if (pos >= raw.length()) {
					throw new PcodeXMLException("Premature end of stream");
				}
				if (raw.charAt(pos) != '>') {
					throw new PcodeXMLException("Parse error");
				}
				currentPos = pos + 1;
				if (id != currentElement) {
					throw new PcodeXMLException("Parse error");
				}
				startOpen = false;
				return;
			}
			if (tok != '>') {
				throw new PcodeXMLException("Parse error");
			}
			startOpen = false;
		}
		pos = scanWhiteSpace(pos);
		if (raw.charAt(pos) != '<') {
			throw new PcodeXMLException("Parse error");
		}
		pos += 1;
		if (pos >= raw.length() || raw.charAt(pos) != '/') {
			throw new PcodeXMLException("Parse error");
		}
		pos = scanWhiteSpace(pos + 1);
		int endpos = scanIdentifier(pos);
		String ident = raw.substring(pos, endpos);
		if (id != ElementId.find(ident)) {
			throw new PcodeXMLException("Expecting end token");
		}
		pos = scanWhiteSpace(endpos);
		if (raw.charAt(pos) != '>') {
			throw new PcodeXMLException("Parse error");
		}
		currentPos = pos + 1;
	}

	@Override
	public void closeElementSkipping(int id) throws PcodeXMLException {
		throw new PcodeXMLException("closeElementSkipping unimplemented");
	}

	@Override
	public int getNextAttributeId() {
		if (!startOpen) {
			return 0;
		}
		try {
			int pos = scanWhiteSpace(currentPos);
			char tok = raw.charAt(pos);
			if (tok == '\"') {
				pos = scanQuote();
				pos = scanWhiteSpace(pos);
				tok = raw.charAt(pos);
			}
			if (tok == '>' || tok == '/') {
				currentPos = pos;
				return 0;
			}
			int endPos = scanIdentifier(pos);
			if (pos == endPos) {
				throw new PcodeXMLException("Parse error");
			}
			String ident = raw.substring(pos, endPos);
			pos = scanWhiteSpace(endPos);
			if (raw.charAt(pos) != '=') {
				throw new PcodeXMLException("Parse error");
			}
			pos = scanWhiteSpace(pos + 1);
			if (raw.charAt(pos) != '\"') {
				throw new PcodeXMLException("Parse error");
			}
			currentPos = pos;
			return AttributeId.find(ident);
		}
		catch (PcodeXMLException e) {
			return 0;
		}
	}

	private void findAttribute(AttributeId attribId) throws PcodeXMLException {
		currentPos = attribStart;
		startOpen = true;
		for (;;) {
			int id = getNextAttributeId();
			if (id == 0) {
				break;
			}
			if (id == attribId.id()) {
				return;
			}
		}
		throw new PcodeXMLException("Missing attribute: " + attribId.name());
	}

	@Override
	public void rewindAttributes() {
		currentPos = attribStart;
		startOpen = true;
	}

	@Override
	public boolean readBool() throws PcodeXMLException {
		String value = scanAttribute();
		return SpecXmlUtils.decodeBoolean(value);
	}

	@Override
	public boolean readBool(AttributeId attribId) throws PcodeXMLException {
		findAttribute(attribId);
		String value = scanAttribute();
		currentPos = attribStart;
		startOpen = true;
		return SpecXmlUtils.decodeBoolean(value);
	}

	@Override
	public long readSignedInteger() throws PcodeXMLException {
		String value = scanAttribute();
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public long readSignedInteger(AttributeId attribId) throws PcodeXMLException {
		findAttribute(attribId);
		String value = scanAttribute();
		currentPos = attribStart;
		startOpen = true;
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public long readUnsignedInteger() throws PcodeXMLException {
		String value = scanAttribute();
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public long readUnsignedInteger(AttributeId attribId) throws PcodeXMLException {
		findAttribute(attribId);
		String value = scanAttribute();
		currentPos = attribStart;
		startOpen = true;
		return SpecXmlUtils.decodeLong(value);
	}

	@Override
	public String readString() throws PcodeXMLException {
		return scanAttribute();
	}

	@Override
	public String readString(AttributeId attribId) throws PcodeXMLException {
		findAttribute(attribId);
		String value = scanAttribute();
		currentPos = attribStart;
		startOpen = true;
		return value;
	}

	@Override
	public AddressSpace readSpace() throws PcodeXMLException {
		String value = scanAttribute();
		AddressSpace spc = addressFactory.getAddressSpace(value);
		if (spc == null) {
			throw new PcodeXMLException("Unknown address space: " + value);
		}
		return spc;
	}

	@Override
	public AddressSpace readSpace(AttributeId attribId) throws PcodeXMLException {
		findAttribute(attribId);
		String value = scanAttribute();
		currentPos = attribStart;
		startOpen = true;
		AddressSpace spc = addressFactory.getAddressSpace(value);
		if (spc == null) {
			throw new PcodeXMLException("Unknown address space: " + value);
		}
		return spc;
	}

}
