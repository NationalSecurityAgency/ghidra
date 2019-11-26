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

import ghidra.program.model.data.DataType;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * ParamMeasure
 * 
 * 
 *
 */

public class ParamMeasure {
	private Varnode vn;
	private DataType dt;
	private Integer rank;

	/**
	 * Constructs a ParamMeasure Object.
	 * <b>The ParamMeasure will be empty until {@link #readXml} is invoked.</b>
	 */
	public ParamMeasure() {
		vn = null;
		dt = null;
		rank = null;
	}

	public boolean isEmpty() {
		if (vn == null)
			return true;
		return false;
	}

	/**
	 * Create a ParamMeasure object by parsing the XML elements
	 * @param parser xml parser
	 * @param factory pcode factory
	 * @throws PcodeXMLException if an error occurs when reading the xml.
	 */
	public void readXml(XmlPullParser parser, PcodeFactory factory) throws PcodeXMLException {
		vn = Varnode.readXML(parser, factory);
		dt = factory.getDataTypeManager().readXMLDataType(parser);
		XmlElement rankel = parser.start("rank");
		String strVal = rankel.getAttribute("val");
		rank = SpecXmlUtils.decodeInt(strVal);
		parser.end(rankel);
	}

	public Varnode getVarnode() {
		return vn;
	}

	public DataType getDataType() {
		return dt;
	}

	public Integer getRank() {
		return rank;
	}
}
