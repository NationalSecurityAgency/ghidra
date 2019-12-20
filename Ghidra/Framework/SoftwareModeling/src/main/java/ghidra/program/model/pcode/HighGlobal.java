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

/**
 * 
 *
 * All references (per function) to a single global variable
 */
public class HighGlobal extends HighVariable {

	private HighSymbol symbol;

	/**
	 * Constructor for use with restoreXml
	 * @param high is the HighFunction this global is accessed by
	 */
	public HighGlobal(HighFunction high) {
		super(high);
	}

	public HighGlobal(HighSymbol sym, Varnode vn, Varnode[] inst) {
		super(sym.getName(), sym.getDataType(), vn, inst, sym.getHighFunction());
		symbol = sym;
	}

	@Override
	public HighSymbol getSymbol() {
		return symbol;
	}

	@Override
	public void restoreXml(XmlPullParser parser) throws PcodeXMLException {
		XmlElement el = parser.start("high");
		long symref = SpecXmlUtils.decodeLong(el.getAttribute("symref"));
		String attrString = el.getAttribute("offset");
		offset = -1;
		if (attrString != null) {
			offset = SpecXmlUtils.decodeInt(attrString);
		}
		restoreInstances(parser, el);
		if (symref == 0) {
			throw new PcodeXMLException("Missing symref attribute in <high> tag");
		}
		symbol = function.getGlobalSymbolMap().getSymbol(symref);
		if (symbol == null) {	// If we don't already have symbol, synthesize it
			DataType symbolType;
			int symbolSize;
			if (offset < 0) {		// Variable type and size matches symbol
				symbolType = type;
				symbolSize = getSize();
			}
			else {
				symbolType = null;
				symbolSize = -1;
			}
			GlobalSymbolMap globalMap = function.getGlobalSymbolMap();
			symbol = globalMap.populateSymbol(symref, symbolType, symbolSize);
			if (symbol == null) {
				Address addr = represent.getAddress();
				if (offset > 0) {
					addr = addr.subtract(offset);
				}
				symbol = globalMap.newSymbol(symref, addr, symbolType, symbolSize);
				if (symbol == null) {
					throw new PcodeXMLException("Bad global storage: " + addr.toString());
				}
			}
		}
		if (offset < 0) {
			name = symbol.getName();
		}
		symbol.setHighVariable(this);

		parser.end(el);
	}
}
