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

/**
 * A specialized HighSymbol that directs the decompiler to use a specific field of a union,
 * when interpreting a particular PcodeOp that accesses a Varnode whose data-type involves the
 * union. The symbol is stored as a dynamic variable annotation.  The data-type must either be the
 * union itself or a pointer to the union. The firstUseOffset and dynamic hash
 * identify the particular PcodeOp and Varnode affected.  The field number is the ordinal
 * of the desired field (DataTypeComponent) within the union.  It is currently stored by
 * encoding it in the symbol name.
 */
public class UnionFacetSymbol extends HighSymbol {
	public static String BASENAME = "unionfacet";
	private int fieldNumber;		// Ordinal of field within union being selected

	public UnionFacetSymbol(long uniqueId, String nm, DataType dt, int fldNum, HighFunction func) {
		super(uniqueId, nm, dt, func);
		category = 2;
		fieldNumber = fldNum;
	}

	@Override
	public void saveXML(StringBuilder buf) {
		buf.append("<facetsymbol");
		saveXMLHeader(buf);
		SpecXmlUtils.encodeSignedIntegerAttribute(buf, "field", fieldNumber);
		buf.append(">\n");
		dtmanage.buildTypeRef(buf, type, getSize());
		buf.append("</facetsymbol>\n");
	}

	/**
	 * Generate an automatic symbol name, given a field number and address
	 * @param fldNum is the field number
	 * @param addr is the Address
	 * @return the name
	 */
	public static String buildSymbolName(int fldNum, Address addr) {
		StringBuilder buffer = new StringBuilder();
		buffer.append(BASENAME).append(fldNum + 1).append('_');
		buffer.append(Long.toHexString(addr.getOffset()));
		return buffer.toString();
	}

	/**
	 * The actual field number is encoded in the symbol name
	 * @param nm is the symbol name
	 * @return the field number or -1 if we cannot parse
	 */
	public static int extractFieldNumber(String nm) {
		int pos = nm.indexOf(BASENAME);
		if (pos < 0) {
			return -1;
		}
		int endpos = nm.indexOf('_', pos);
		if (endpos < 0) {
			return -1;
		}
		return Integer.decode(nm.substring(pos + BASENAME.length(), endpos)) - 1;
	}
}
