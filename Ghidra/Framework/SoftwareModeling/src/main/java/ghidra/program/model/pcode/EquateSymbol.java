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

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

public class EquateSymbol extends HighSymbol {

	public static final int FORMAT_DEFAULT = 0;
	public static final int FORMAT_HEX = 1;
	public static final int FORMAT_DEC = 2;
	public static final int FORMAT_OCT = 3;
	public static final int FORMAT_BIN = 4;
	public static final int FORMAT_CHAR = 5;

	private long value;			// Value of the equate
	private int convert;		// Non-zero if this is a conversion equate
	
	public EquateSymbol(HighFunction func) {
		super(func);
	}

	public EquateSymbol(long uniqueId, String nm, long val, HighFunction func, Address addr,
			long hash) {
		super(uniqueId, nm, DataType.DEFAULT, func);
		category = 1;
		value = val;
		convert = FORMAT_DEFAULT;
		DynamicEntry entry = new DynamicEntry(this, addr, hash);
		addMapEntry(entry);
	}
	
	public EquateSymbol(long uniqueId, int conv, long val, HighFunction func, Address addr,
			long hash) {
		super(uniqueId, "", DataType.DEFAULT, func);
		category = 1;
		value = val;
		convert = conv;
		DynamicEntry entry = new DynamicEntry(this, addr, hash);
		addMapEntry(entry);
	}

	public long getValue() { return value; }

	public int getConvert() {
		return convert;
	}

	@Override
	public void restoreXML(XmlPullParser parser) throws PcodeXMLException {
		XmlElement symel = parser.start("equatesymbol");
		restoreXMLHeader(symel);
		type = DataType.DEFAULT;
		convert = FORMAT_DEFAULT;
		String formString = symel.getAttribute("format");
		if (formString != null) {
			if (formString.equals("hex")) {
				convert = FORMAT_HEX;
			}
			else if (formString.equals("dec")) {
				convert = FORMAT_DEC;
			}
			else if (formString.equals("char")) {
				convert = FORMAT_CHAR;
			}
			else if (formString.equals("oct")) {
				convert = FORMAT_OCT;
			}
			else if (formString.equals("bin")) {
				convert = FORMAT_BIN;
			}
		}
		parser.start("value");
		value = SpecXmlUtils.decodeLong(parser.end().getText());			// End <value> tag
		parser.end(symel);
	}

	@Override
	public void saveXML(StringBuilder buf) {
		buf.append("<equatesymbol");
		saveXMLHeader(buf);
		if (convert != 0) {
			String formString = "hex";
			if (convert == FORMAT_HEX) {
				// Most common case
			}
			else if (convert == FORMAT_DEC) {
				formString = "dec";
			}
			else if (convert == FORMAT_OCT) {
				formString = "oct";
			}
			else if (convert == FORMAT_BIN) {
				formString = "bin";
			}
			else if (convert == FORMAT_CHAR) {
				formString = "char";
			}
			SpecXmlUtils.encodeStringAttribute(buf, "format", formString);
		}
		buf.append(">\n");
		buf.append("  <value>0x");
		buf.append(Long.toHexString(value));
		buf.append("</value>\n");
		buf.append("</equatesymbol>\n");
	}
	
	public static int convertName(String nm,long val) {
		int pos = 0;
		char firstChar = nm.charAt(pos++);
		if (firstChar == '-') {
			if (nm.length() > pos) {
				firstChar = nm.charAt(pos++);
			}
			else {
				return FORMAT_DEFAULT;			// Bad equate name, just print number normally
			}
		}
		if (firstChar == '\'') {
			return FORMAT_CHAR;
		}
		if (firstChar == '"') {					// Multi-character conversion
			return FORMAT_DEC;					// not currently supported, just format in decimal
		}
		if (firstChar < '0' || firstChar > '9') {
			return -1;			// Don't treat as a conversion
		}
		char lastChar = nm.charAt(nm.length() - 1);
		if (lastChar == 'b') {
			return FORMAT_BIN;
		}
		else if (lastChar == 'o') {
			return FORMAT_OCT;
		}
		int format = FORMAT_DEC;
		if (firstChar == '0') {
			format = FORMAT_DEC;
			if (nm.length() >= (pos + 1)) {
				char c = nm.charAt(pos);
				if (c == 'x') {
					format = FORMAT_HEX;
				}
			}
		}
		return format;
	}
}
