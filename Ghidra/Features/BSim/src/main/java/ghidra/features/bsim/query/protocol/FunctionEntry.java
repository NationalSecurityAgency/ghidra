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
package ghidra.features.bsim.query.protocol;

import java.io.IOException;
import java.io.Writer;

import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * Identifying information for a function within a single executable
 *
 */
public class FunctionEntry {
	public String funcName;			// Name of the function within the executable
	public int spaceid;			// id of the Address Space of the function
	public long address;			// Address of the function

	private FunctionEntry() {
		// Used for restoreXml
	}
	
	public FunctionEntry(FunctionDescription desc) {
		funcName = desc.getFunctionName();
		spaceid = desc.getSpaceID();
		address = desc.getAddress();
	}

	public void saveXml(Writer writer) throws IOException {
		writer.append("<fentry name=\"");
		SpecXmlUtils.xmlEscapeWriter(writer, funcName);
		writer.append("\" spaceid=\"");
		writer.append(Long.toString(spaceid));
		writer.append("\" addr=\"0x");
		writer.append(Long.toHexString(address));
		writer.append("\"/>\n");
	}
	
	public static FunctionEntry restoreXml(XmlPullParser parser) {
		FunctionEntry functionEntry = new FunctionEntry();
		XmlElement startEl = parser.start("fentry");
		functionEntry.funcName = startEl.getAttribute("name");
		functionEntry.spaceid = SpecXmlUtils.decodeInt(startEl.getAttribute("spaceid"));
		functionEntry.address = SpecXmlUtils.decodeLong(startEl.getAttribute("addr"));
		parser.end(startEl);
		return functionEntry;
	}
}
