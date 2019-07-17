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

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.PcodeFactory;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;

/**
 * A C code token representing a structure field.
 *
 */
public class ClangFieldToken extends ClangToken {
	private DataType datatype;			// Structure from which this field is a part
	private int offset;					// Byte offset of the field within the structure

	public ClangFieldToken(ClangNode par) {
		super(par);
		datatype = null;
	}
	
	/**
	 * @return the structure datatype associated with this field token
	 */
	public DataType getDataType() {
		return datatype;
	}
	
	/**
	 * @return the byte offset of this field with its structure
	 */
	public int getOffset() {
		return offset;
	}
	
	@Override
    public void restoreFromXML(XmlElement el,XmlElement end,PcodeFactory pfactory) {
		super.restoreFromXML(el,end,pfactory);
		String datatypestring = el.getAttribute("name");		// Name of the structure
		if (datatypestring != null)
			datatype = pfactory.getDataTypeManager().findBaseType(datatypestring,el.getAttribute("id"));
		String offsetstring = el.getAttribute(ClangXML.OFFSET);
		if (offsetstring != null)
			offset = SpecXmlUtils.decodeInt(offsetstring);
	}

}
